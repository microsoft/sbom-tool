// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// This class generates an array of external document references.
/// </summary>
public class ExternalDocumentReferenceGenerator : IJsonArrayGenerator<ExternalDocumentReferenceGenerator>
{
    private readonly ILogger log;

    private readonly ISbomConfigProvider sbomConfigs;

    private readonly IEnumerable<ISourcesProvider> sourcesProviders;

    private readonly IRecorder recorder;

    public ExternalDocumentReferenceGenerator(
        ILogger log,
        ISbomConfigProvider sbomConfigs,
        IEnumerable<ISourcesProvider> sourcesProviders,
        IRecorder recorder)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.sourcesProviders = sourcesProviders ?? throw new ArgumentNullException(nameof(sourcesProviders));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    public async Task<IList<FileValidationResult>> GenerateAsync()
    {
        using (recorder.TraceEvent(Events.ExternalDocumentReferenceGeneration))
        {
            IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

            IEnumerable<ISourcesProvider> sourcesProviders = this.sourcesProviders
                .Where(s => s.IsSupported(ProviderType.ExternalDocumentReference));
            if (!sourcesProviders.Any())
            {
                log.Debug($"No source providers found for {ProviderType.ExternalDocumentReference}");
                return totalErrors;
            }

            // Write the start of the array, if supported.
            IList<ISbomConfig> externalRefArraySupportingConfigs = new List<ISbomConfig>();
            foreach (var manifestInfo in sbomConfigs.GetManifestInfos())
            {
                var config = sbomConfigs.Get(manifestInfo);
                if (config.MetadataBuilder.TryGetExternalRefArrayHeaderName(out string externalRefArrayHeaderName))
                {
                    externalRefArraySupportingConfigs.Add(config);
                    config.JsonSerializer.StartJsonArray(externalRefArrayHeaderName);
                }
            }

            foreach (var sourcesProvider in sourcesProviders)
            {
                var (jsonDocResults, errors) = sourcesProvider.Get(externalRefArraySupportingConfigs);

                // Collect all the json elements and write to the serializer.
                int totalJsonDocumentsWritten = 0;

                await foreach (JsonDocWithSerializer jsonResults in jsonDocResults.ReadAllAsync())
                {
                    jsonResults.Serializer.Write(jsonResults.Document);
                    totalJsonDocumentsWritten++;
                }

                await foreach (FileValidationResult error in errors.ReadAllAsync())
                {
                    totalErrors.Add(error);
                }
            }

            // Write the end of the array.
            foreach (SbomConfig config in externalRefArraySupportingConfigs)
            {
                config.JsonSerializer.EndJsonArray();
            }

            return totalErrors;
        }
    }
}
