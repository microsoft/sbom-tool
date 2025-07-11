// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows;

public class SbomAggregationWorkflow : IWorkflow<SbomAggregationWorkflow>
{
    public const string WorkingDirPrefix = "sbom-aggregation-";

    private readonly ILogger logger;
    private readonly IRecorder recorder;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigFactory sbomConfigFactory;
    private readonly ISbomConfigProvider sbomConfigProvider;
    private readonly ISPDXFormatDetector spdxFormatDetector;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IMetadataBuilderFactory metadataBuilderFactory;
    private readonly IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow;
    private readonly ISbomValidationWorkflowFactory sbomValidationWorkflowFactory;
    private readonly IReadOnlyDictionary<ManifestInfo, IMergeableContentProvider> contentProviders;
    private string workingDir;

    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;

    public SbomAggregationWorkflow(
        ILogger logger,
        IRecorder recorder,
        IConfiguration configuration,
        IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow,
        ISbomValidationWorkflowFactory sbomValidationWorkflowFactory,
        ISbomConfigFactory sbomConfigFactory,
        ISbomConfigProvider sbomConfigProvider,
        ISPDXFormatDetector spdxFormatDetector,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory,
        IEnumerable<IMergeableContentProvider> mergeableContentProviders)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigFactory = sbomConfigFactory ?? throw new ArgumentNullException(nameof(sbomConfigFactory));
        this.sbomConfigProvider = sbomConfigProvider ?? throw new ArgumentNullException(nameof(sbomConfigProvider));
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
        using (recorder.TraceEvent(Events.SbomAggregationWorkflow))
        {
            try
            {
                var allVersionAggregationSources = ArtifactInfoMap.Select(artifact => GetSbomsToAggregate(artifact.Key, artifact.Value))
                .Where(l => l != null)
                .SelectMany(l => l);

                var aggregationSources = allVersionAggregationSources.Where(s => s.SbomConfig.ManifestInfo.Equals(Constants.SPDX22ManifestInfo));
                var non22Sboms = allVersionAggregationSources.Select(s => s.SbomConfig.ManifestJsonFilePath).Except(aggregationSources.Select(s => s.SbomConfig.ManifestJsonFilePath));
                if (non22Sboms.Any())
                {
                    logger.Information($"The aggregate action only supports SPDX 2.2. The following non-SPDX 2.2 SBOMs are being ignored:\n{string.Join('\n', non22Sboms)}");
                }

                if (aggregationSources == null || !aggregationSources.Any())
                {
                    logger.Information($"No valid SBOMs detected.");
                    return false;
                }
                else
                {
                    logger.Information($"Running aggregation on the following SBOMs:\n{string.Join('\n', aggregationSources.Select(s => s.SbomConfig.ManifestJsonFilePath))}");
                }

                workingDir = fileSystemUtils.CreateTempSubDirectory(WorkingDirPrefix);

                return await ValidateSourceSbomsAsync(aggregationSources) && await GenerateAggregatedSbom(aggregationSources);
            }
            catch (Exception e)
            {
                recorder.RecordException(e);
                logger.Error("Encountered an error while generating the manifest.");
                logger.Error($"Error details: {e.Message}");

                return false;
            }
        }
    }

    private IEnumerable<AggregationSource> GetSbomsToAggregate(string artifactPath, ArtifactInfo info)
    {
        var manifestDirPath = info?.ExternalManifestDir ?? fileSystemUtils.JoinPaths(artifactPath, Constants.ManifestFolder);
        var isValidSpdxFormat = spdxFormatDetector.TryGetSbomsWithVersion(manifestDirPath, out var detectedSboms);
        if (!isValidSpdxFormat)
        {
            logger.Warning($"No SBOMs located in {manifestDirPath} of a recognized SPDX format.");
            return null;
        }

        return detectedSboms.Select((sbom) => new AggregationSource(info, sbomConfigFactory.Get(sbom.manifestInfo, manifestDirPath, metadataBuilderFactory), artifactPath));
    }

    private async Task<bool> ValidateSourceSbomsAsync(IEnumerable<AggregationSource> aggregationSources)
    {
        var result = true;
        foreach (var source in aggregationSources)
        {
            var identifier = source.Identifier;
            var workflowResult = false;
            var originalManifestDirPath = configuration.ManifestDirPath;
            try
            {
                configuration.ValidateSignature = new ConfigurationSetting<bool>(!source.ArtifactInfo.SkipSigningCheck ?? true);
                configuration.IgnoreMissing = new ConfigurationSetting<bool>(source.ArtifactInfo.IgnoreMissingFiles ?? false);
                configuration.BuildDropPath = new ConfigurationSetting<string>(source.BuildDropPath);
                configuration.OutputPath = new ConfigurationSetting<string>(fileSystemUtils.JoinPaths(workingDir, $"validation-results-{identifier}.json"));
                configuration.ManifestInfo = new ConfigurationSetting<IList<ManifestInfo>>(new List<ManifestInfo>() { source.SbomConfig.ManifestInfo });
                configuration.ManifestDirPath = BuildManifestDirPathForSource(source);

                Console.WriteLine($"Running validation for {source.SbomConfig.ManifestJsonFilePath} with identifier {identifier}. Writing output results to {configuration.OutputPath.Value}.");
                if (!configuration.ValidateSignature.Value)
                {
                    logger.Warning($"Signature validation disabled for SBOM with path {source.SbomConfig.ManifestJsonFilePath} and identifier {identifier}.");
                }

                var workflow = sbomValidationWorkflowFactory.Get(configuration, source.SbomConfig, identifier);
                workflowResult = await workflow.RunAsync();
            }
            finally
            {
                configuration.BuildDropPath.Value = null;
                configuration.OutputPath.Value = null;
                configuration.ManifestDirPath = originalManifestDirPath;

                result = workflowResult && result;
            }
        }

        return result;
    }

    private ConfigurationSetting<string> BuildManifestDirPathForSource(AggregationSource source)
    {
        if (source.ArtifactInfo.ExternalManifestDir is null)
        {
            return new ConfigurationSetting<string>
            {
                Value = fileSystemUtils.JoinPaths(source.BuildDropPath, Constants.ManifestFolder),
                Source = SettingSource.Default
            };
        }

        return new ConfigurationSetting<string>
        {
            Value = source.ArtifactInfo.ExternalManifestDir,
            Source = SettingSource.JsonConfig
        };
    }

    private async Task<bool> GenerateAggregatedSbom(IEnumerable<AggregationSource> aggregationSources)
    {
        if (!TryGetMergeableContent(aggregationSources, out var mergeableContents))
        {
            return false;
        }

        SetConfigurationForAggregation(mergeableContents);

        // The configs contain the input paths. We need to clear them so we write to the correct locations.
        sbomConfigProvider.ClearCache();

        return await sbomGenerationWorkflow.RunAsync().ConfigureAwait(false);
    }

    private void SetConfigurationForAggregation(IEnumerable<MergeableContent> mergeableContents)
    {
        var buildDropPath = Path.Combine(workingDir, "aggregated-build-drop");
        fileSystemUtils.CreateDirectory(buildDropPath);

        configuration.ManifestInfo = new ConfigurationSetting<IList<ManifestInfo>>(new List<ManifestInfo> { Constants.SPDX22ManifestInfo });
        configuration.BuildDropPath = new ConfigurationSetting<string>(buildDropPath);
        configuration.BuildComponentPath = new ConfigurationSetting<string>(buildDropPath);
        configuration.PackagesList = new ConfigurationSetting<IEnumerable<SbomPackage>>(mergeableContents.ToMergedPackages());
        configuration.PackageDependenciesList = new ConfigurationSetting<IEnumerable<KeyValuePair<string, string>>>(mergeableContents.ToMergedDependsOnRelationships());
    }

    private bool TryGetMergeableContent(IEnumerable<AggregationSource> aggregationSources, out IEnumerable<MergeableContent> mergeableContents)
    {
        mergeableContents = null; // Until proven otherwise

        var contents = new List<MergeableContent>();

        // Incorporate the source SBOMs in the aggregated SBOM generation workflow.
        foreach (var aggregationSource in aggregationSources)
        {
            var sbomConfig = aggregationSource.SbomConfig;
            var sbomPath = aggregationSource.SbomConfig.ManifestJsonFilePath;
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

            recorder.RecordAggregationSource(aggregationSource.Identifier, mergeableContent.Packages.Count(), mergeableContent.Relationships.Count());

            contents.Add(mergeableContent);
        }

        mergeableContents = contents;
        return true;
    }
}
