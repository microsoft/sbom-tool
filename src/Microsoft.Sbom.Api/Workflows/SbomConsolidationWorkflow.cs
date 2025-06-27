// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils;
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
    private readonly ISPDXFormatDetector sPDXFormatDetector;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IMetadataBuilderFactory metadataBuilderFactory;
    private readonly IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow;
    private readonly IReadOnlyDictionary<ManifestInfo, IMergeableContentProvider> contentProviders;

    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;

    internal IEnumerable<(ManifestInfo, string)> SourceSbomsTemp { get; set; } = Enumerable.Empty<(ManifestInfo, string)>(); // Stub property for testing, will remove soon

    public SbomConsolidationWorkflow(
        ILogger logger,
        IConfiguration configuration,
        IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow,
        ISbomConfigFactory sbomConfigFactory,
        ISPDXFormatDetector sPDXFormatDetector,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory,
        IEnumerable<IMergeableContentProvider> mergeableContentProviders)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigFactory = sbomConfigFactory ?? throw new ArgumentNullException(nameof(sbomConfigFactory));
        this.sPDXFormatDetector = sPDXFormatDetector ?? throw new ArgumentNullException(nameof(sPDXFormatDetector));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.metadataBuilderFactory = metadataBuilderFactory ?? throw new ArgumentNullException(nameof(metadataBuilderFactory));
        this.sbomGenerationWorkflow = sbomGenerationWorkflow ?? throw new ArgumentNullException(nameof(sbomGenerationWorkflow));

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
        var sbomsToConsolidate = ArtifactInfoMap.Select(artifact => GetSbomsToConsolidate(artifact.Key, artifact.Value))
            .Where(l => l != null)
            .SelectMany(l => l);
        if (sbomsToConsolidate == null || !sbomsToConsolidate.Any())
        {
            logger.Information($"No valid SBOMs detected.");
            return false;
        }
        else
        {
            logger.Information($"Running consolidation on the following SBOMs:\n{string.Join('\n', sbomsToConsolidate.Select(s => s.config.ManifestJsonFilePath))}");
        }

        return await ValidateSourceSbomsAsync(sbomsToConsolidate) && await GenerateConsolidatedSbom();
    }

    private IEnumerable<(ISbomConfig config, ArtifactInfo info)> GetSbomsToConsolidate(string artifactPath, ArtifactInfo info)
    {
        var manifestDirPath = info?.ExternalManifestDir ?? fileSystemUtils.JoinPaths(artifactPath, Constants.ManifestFolder);
        var isValidSpdxFormat = sPDXFormatDetector.TryGetSbomsWithVersion(manifestDirPath, out var detectedSboms);
        if (!isValidSpdxFormat)
        {
            logger.Information($"No SBOMs located in {manifestDirPath} of a recognized SPDX format.");
            return null;
        }

        return detectedSboms.Select((sbom) => (sbomConfigFactory.Get(sbom.manifestInfo, manifestDirPath, metadataBuilderFactory), info));
    }

    private async Task<bool> ValidateSourceSbomsAsync(IEnumerable<(ISbomConfig config, ArtifactInfo info)> sbomsToValidate)
    {
        var validationWorkflows = sbomsToValidate
            .Select(async sbom => await Task.FromResult(true)); // TODO: Run validation workflow
        var results = await Task.WhenAll(validationWorkflows);
        return results.All(b => b);
    }

    private async Task<bool> GenerateConsolidatedSbom()
    {
        if (!TryGetMergeableContent(out var mergeableContents))
        {
            return false;
        }

        // TODO : How do we pass mergeableContents into the generation workflow?
        return await sbomGenerationWorkflow.RunAsync().ConfigureAwait(false);
    }

    private bool TryGetMergeableContent(out IEnumerable<MergeableContent> mergeableContents)
    {
        mergeableContents = null; // Until proven otherwise

        var contents = new List<MergeableContent>();

        if (!SourceSbomsTemp.Any())
        {
            logger.Error("No source SBOMs provided for consolidation.");
            return false;
        }

        // Incorporate the source SBOMs in the consolidated SBOM generation workflow.
        foreach (var sourceSbom in SourceSbomsTemp)
        {
            var (manifestInfo, sbomPath) = sourceSbom;
            if (!contentProviders.TryGetValue(manifestInfo, out var contentProvider))
            {
                logger.Error("No content provider found for manifest info: {ManifestInfo}", manifestInfo);
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
