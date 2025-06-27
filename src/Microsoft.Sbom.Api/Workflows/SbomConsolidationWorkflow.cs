// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows;

public class SbomConsolidationWorkflow : IWorkflow<SbomConsolidationWorkflow>
{
    private readonly ILogger logger;
    private readonly IConfiguration configuration;
    private readonly IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow;
    private readonly IReadOnlyDictionary<ManifestInfo, IMergeableContentProvider> contentProviders;

#pragma warning disable IDE0051 // We'll use this soon.
    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;
#pragma warning restore IDE0051 // We'll use this soon.

    internal IEnumerable<(ManifestInfo, string)> SourceSbomsTemp { get; set; } = Enumerable.Empty<(ManifestInfo, string)>(); // Stub property for testing, will remove soon

    public SbomConsolidationWorkflow(
        ILogger logger,
        IConfiguration configuration,
        IWorkflow<SbomGenerationWorkflow> sbomGenerationWorkflow,
        IEnumerable<IMergeableContentProvider> mergeableContentProviders)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
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
        logger.Information("Placeholder SBOM consolidation workflow executed.");

        return ValidateSourceSboms() && await GenerateConsolidatedSbom();
    }

    private bool ValidateSourceSboms()
    {
        // TODO : Implement the source SBOMs.`
        return true;
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
