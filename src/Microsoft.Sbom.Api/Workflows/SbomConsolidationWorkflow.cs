// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows;

public class SbomConsolidationWorkflow : IWorkflow<SbomConsolidationWorkflow>
{
    private readonly ILogger logger;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigFactory sbomConfigFactory;
    private readonly ISPDXFormatDetector spdxFormatDetector;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IMetadataBuilderFactory metadataBuilderFactory;
    private readonly IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow;
    private readonly ISbomValidationWorkflowFactory sbomValidationWorkflowFactory;
    private readonly IReadOnlyDictionary<ManifestInfo, IMergeableContentProvider> contentProviders;

    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;

    public SbomConsolidationWorkflow(
        ILogger logger,
        IConfiguration configuration,
        IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow,
        ISbomValidationWorkflowFactory sbomValidationWorkflowFactory,
        ISbomConfigFactory sbomConfigFactory,
        ISPDXFormatDetector spdxFormatDetector,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory,
        IEnumerable<IMergeableContentProvider> mergeableContentProviders)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigFactory = sbomConfigFactory ?? throw new ArgumentNullException(nameof(sbomConfigFactory));
        this.spdxFormatDetector = spdxFormatDetector ?? throw new ArgumentNullException(nameof(spdxFormatDetector));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.metadataBuilderFactory = metadataBuilderFactory ?? throw new ArgumentNullException(nameof(metadataBuilderFactory));
        this.sbomGenerationWorkflow = sbomGenerationWorkflow ?? throw new ArgumentNullException(nameof(sbomGenerationWorkflow));
        this.sbomValidationWorkflowFactory = sbomValidationWorkflowFactory ?? throw new ArgumentNullException(nameof(sbomValidationWorkflowFactory));

        ArgumentNullException.ThrowIfNull(mergeableContentProviders, nameof(mergeableContentProviders));
        if (!mergeableContentProviders.Any())
        {
            throw new ArgumentException("The mergeable content providers collection cannot be empty.", nameof(mergeableContentProviders));
        }

        var providers = new Dictionary<ManifestInfo, IMergeableContentProvider>();
        foreach (var provider in mergeableContentProviders)
        {
            providers.Add(provider.ManifestInfo, provider);
        }

        contentProviders = providers;
    }

    /// <inheritdoc/>
    public virtual async Task<bool> RunAsync()
    {
        var consolidationSources = ArtifactInfoMap.Select(artifact => GetSbomsToConsolidate(artifact.Key, artifact.Value))
            .Where(l => l != null)
            .SelectMany(l => l);
        if (consolidationSources == null || !consolidationSources.Any())
        {
            logger.Information($"No valid SBOMs detected.");
            return false;
        }
        else
        {
            logger.Information($"Running consolidation on the following SBOMs:\n{string.Join('\n', consolidationSources.Select(s => s.SbomConfig.ManifestJsonFilePath))}");
        }

        return await ValidateSourceSbomsAsync(consolidationSources) && await GenerateConsolidatedSbom(consolidationSources);
    }

    private IEnumerable<ConsolidationSource> GetSbomsToConsolidate(string artifactPath, ArtifactInfo info)
    {
        var manifestDirPath = info?.ExternalManifestDir ?? fileSystemUtils.JoinPaths(artifactPath, Constants.ManifestFolder);
        var isValidSpdxFormat = spdxFormatDetector.TryGetSbomsWithVersion(manifestDirPath, out var detectedSboms);
        if (!isValidSpdxFormat)
        {
            logger.Information($"No SBOMs located in {manifestDirPath} of a recognized SPDX format.");
            return null;
        }

        return detectedSboms.Select((sbom) => new ConsolidationSource(info, sbomConfigFactory.Get(sbom.manifestInfo, manifestDirPath, metadataBuilderFactory), artifactPath));
    }

    private async Task<bool> ValidateSourceSbomsAsync(IEnumerable<ConsolidationSource> consolidationSources)
    {
        var result = true;
        foreach (var source in consolidationSources)
        {
            var identifier = Math.Abs(string.GetHashCode(source.SbomConfig.ManifestJsonFilePath)).ToString();
            var defaultOutputPath = configuration.OutputPath;
            var workflowResult = false;
            try
            {
                configuration.ValidateSignature = new ConfigurationSetting<bool>(!source.ArtifactInfo.SkipSigningCheck ?? true);
                configuration.IgnoreMissing = new ConfigurationSetting<bool>(source.ArtifactInfo.IgnoreMissingFiles ?? false);
                configuration.BuildDropPath = new ConfigurationSetting<string>(source.BuildDropPath);
                configuration.OutputPath = new ConfigurationSetting<string>(fileSystemUtils.GetTempFile($"validation-results-{identifier}.json"));

                Console.WriteLine($"Running validation for {source.SbomConfig.ManifestJsonFilePath} with identifier {identifier}. Writing output results to {configuration.OutputPath}.");
                var workflow = sbomValidationWorkflowFactory.Get(configuration, source.SbomConfig, identifier);
                workflowResult = await workflow.RunAsync();
            }
            finally
            {
                configuration.BuildDropPath = null;
                configuration.OutputPath = defaultOutputPath;

                result = workflowResult && result;
            }
        }

        return result;
    }

    private async Task<bool> GenerateConsolidatedSbom(IEnumerable<ConsolidationSource> consolidationSources)
    {
        if (!TryGetMergeableContent(consolidationSources, out var mergeableContents))
        {
            return false;
        }

        // TODO : How do we pass mergeableContents into the generation workflow?
        return await sbomGenerationWorkflow.RunAsync().ConfigureAwait(false);
    }

    private bool TryGetMergeableContent(IEnumerable<ConsolidationSource> consolidationSources, out IEnumerable<MergeableContent> mergeableContents)
    {
        mergeableContents = null; // Until proven otherwise

        var contents = new List<MergeableContent>();

        // Incorporate the source SBOMs in the consolidated SBOM generation workflow.
        foreach (var consolidationSource in consolidationSources)
        {
            var sbomConfig = consolidationSource.SbomConfig;
            var sbomPath = consolidationSource.SbomConfig.ManifestJsonFilePath;
            if (!contentProviders.TryGetValue(sbomConfig.ManifestInfo, out var contentProvider))
            {
                logger.Error("No content provider found for manifest info: {ManifestInfo}", sbomConfig.ManifestInfo);
                return false;
            }

            if (!contentProvider.TryGetContent(sbomPath, out var mergeableContent))
            {
                logger.Error("Failed to get mergeable content from SBOM at path: {SbomPath}", sbomPath);
                return false;
            }

            contents.Add(mergeableContent);
        }

        mergeableContents = contents;
        return true;
    }
}
