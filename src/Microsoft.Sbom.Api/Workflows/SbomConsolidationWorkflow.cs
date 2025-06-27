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

#pragma warning disable IDE0051 // We'll use this soon.
    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;
#pragma warning restore IDE0051 // We'll use this soon.

    public SbomConsolidationWorkflow(ILogger logger, IConfiguration configuration, IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow, ISbomConfigFactory sbomConfigFactory, ISPDXFormatDetector sPDXFormatDetector, IFileSystemUtils fileSystemUtils, IMetadataBuilderFactory metadataBuilderFactory)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigFactory = sbomConfigFactory ?? throw new ArgumentNullException(nameof(sbomConfigFactory));
        this.sPDXFormatDetector = sPDXFormatDetector ?? throw new ArgumentNullException(nameof(sPDXFormatDetector));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.metadataBuilderFactory = metadataBuilderFactory ?? throw new ArgumentNullException(nameof(metadataBuilderFactory));
        this.sbomGenerationWorkflow = sbomGenerationWorkflow ?? throw new ArgumentNullException(nameof(sbomGenerationWorkflow));
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

        return await ValidateSourceSbomsAsync(sbomsToConsolidate) && await GeneratedConsolidatedSbom();
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

    private async Task<bool> GeneratedConsolidatedSbom()
    {
        // TODO : Incorporate the source SBOMs in the consolidated SBOM generation workflow.
        return await sbomGenerationWorkflow.RunAsync().ConfigureAwait(false);
    }
}
