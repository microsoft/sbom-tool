// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// This class generates an array of external document references.
/// </summary>
public class ExternalDocumentReferenceGenerator : IJsonArrayGenerator<ExternalDocumentReferenceGenerator>
{
    private readonly ILogger log;

    private readonly IEnumerable<ISourcesProvider> sourcesProviders;

    private readonly IRecorder recorder;

    public ISbomConfig SbomConfig { get; set; }

    public string SpdxManifestVersion { get; set; }

    public ExternalDocumentReferenceGenerator(
        ILogger log,
        IEnumerable<ISourcesProvider> sourcesProviders,
        IRecorder recorder)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.sourcesProviders = sourcesProviders ?? throw new ArgumentNullException(nameof(sourcesProviders));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    public async Task<GenerateResult> GenerateAsync()
    {
        using (recorder.TraceEvent(Events.ExternalDocumentReferenceGeneration))
        {
            var totalErrors = new List<FileValidationResult>();
            var serializersToJsonDocs = new Dictionary<IManifestToolJsonSerializer, List<JsonDocument>>();

            var sourcesProviders = this.sourcesProviders
                .Where(s => s.IsSupported(ProviderType.ExternalDocumentReference));
            if (!sourcesProviders.Any())
            {
                log.Debug($"No source providers found for {ProviderType.ExternalDocumentReference}");
                return new GenerateResult(totalErrors, serializersToJsonDocs);
            }

            // Write the start of the array, if supported.
            IList<ISbomConfig> externalRefArraySupportingConfigs = new List<ISbomConfig>();
            var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(SpdxManifestVersion);
            serializationStrategy.AddToFilesSupportingConfig(ref externalRefArraySupportingConfigs, this.SbomConfig);

            foreach (var sourcesProvider in sourcesProviders)
            {
                var (jsonDocResults, errors) = sourcesProvider.Get(externalRefArraySupportingConfigs);

                // Collect all the json elements and write to the serializer.
                var totalJsonDocumentsWritten = 0;

                await foreach (var jsonResults in jsonDocResults.ReadAllAsync())
                {
                    if (!serializersToJsonDocs.ContainsKey(jsonResults.Serializer))
                    {
                        serializersToJsonDocs[jsonResults.Serializer] = new List<JsonDocument>();
                    }

                    serializersToJsonDocs[jsonResults.Serializer].Add(jsonResults.Document);
                    totalJsonDocumentsWritten++;
                }

                log.Debug($"Wrote {totalJsonDocumentsWritten} ExternalDocumentReference elements in the SBOM.");

                await foreach (var error in errors.ReadAllAsync())
                {
                    totalErrors.Add(error);
                }
            }

            return new GenerateResult(totalErrors, serializersToJsonDocs);
        }
    }
}
