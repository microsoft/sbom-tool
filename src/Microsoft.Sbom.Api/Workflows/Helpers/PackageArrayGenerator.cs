// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Generates a packages array that contains a list of all the packages that are referenced in this project.
/// </summary>
public class PackageArrayGenerator : IJsonArrayGenerator<PackageArrayGenerator>
{
    private readonly ILogger log;

    private readonly IEnumerable<ISourcesProvider> sourcesProviders;

    private readonly IRecorder recorder;

    private readonly ISbomConfigProvider sbomConfigs;

    public ISbomConfig SbomConfig { get; set; }

    public string SpdxManifestVersion { get; set; }

    public PackageArrayGenerator(
        ILogger log,
        IEnumerable<ISourcesProvider> sourcesProviders,
        IRecorder recorder,
        ISbomConfigProvider sbomConfigs)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.sourcesProviders = sourcesProviders ?? throw new ArgumentNullException(nameof(sourcesProviders));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
    }

    public async Task<GenerateResult> GenerateAsync()
    {
        using (recorder.TraceEvent(Events.PackagesGeneration))
        {
            var totalErrors = new List<FileValidationResult>();

            var sourcesProvider = this.sourcesProviders
                .FirstOrDefault(s => s.IsSupported(ProviderType.Packages));

            // Write the start of the array, if supported.
            IList<ISbomConfig> packagesArraySupportingConfigs = new List<ISbomConfig>();
            var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(SpdxManifestVersion);
            serializationStrategy.AddToPackagesSupportingConfig(ref packagesArraySupportingConfigs, this.SbomConfig);

            var (jsonDocResults, errors) = sourcesProvider.Get(packagesArraySupportingConfigs);

            // 6. Collect all the json elements to be written to the serializer.
            var totalJsonDocumentsWritten = 0;
            var serializersToJsonDocs = new Dictionary<IManifestToolJsonSerializer, List<JsonDocument>>();

            await foreach (var jsonDocResult in jsonDocResults.ReadAllAsync())
            {
                if (!serializersToJsonDocs.ContainsKey(jsonDocResult.Serializer))
                {
                    serializersToJsonDocs[jsonDocResult.Serializer] = new List<JsonDocument>();
                }

                serializersToJsonDocs[jsonDocResult.Serializer].Add(jsonDocResult.Document);
                totalJsonDocumentsWritten++;
            }

            if (totalJsonDocumentsWritten == 0)
            {
                log.Warning($"There were no packages detected during the generation workflow.");
            }

            log.Debug($"Wrote {totalJsonDocumentsWritten} package elements in the SBOM.");

            // +1 is added to the totalJsonDocumentsWritten to account for the root package of the SBOM.
            recorder.RecordTotalNumberOfPackages(totalJsonDocumentsWritten + 1);
            await foreach (var error in errors.ReadAllAsync())
            {
                totalErrors.Add(error);
            }

            foreach (var sbomConfig in packagesArraySupportingConfigs)
            {
                // Write the root package information to SBOM.
                if (sbomConfig.MetadataBuilder.TryGetRootPackageJson(sbomConfigs, out var generationResult))
                {
                    if (!serializersToJsonDocs.ContainsKey(sbomConfig.JsonSerializer))
                    {
                        serializersToJsonDocs[sbomConfig.JsonSerializer] = new List<JsonDocument>();
                    }

                    serializersToJsonDocs[sbomConfig.JsonSerializer].Add(generationResult?.Document);

                    sbomConfig.Recorder.RecordRootPackageId(generationResult?.ResultMetadata?.EntityId);
                    sbomConfig.Recorder.RecordDocumentId(generationResult?.ResultMetadata?.DocumentId);
                }

                // Write creation info to SBOM. Creation info element is only applicable for SPDX 3.0 and above.
                if (sbomConfig.MetadataBuilder.TryGetCreationInfoJson(sbomConfigs, out generationResult))
                {
                    if (!serializersToJsonDocs.ContainsKey(sbomConfig.JsonSerializer))
                    {
                        serializersToJsonDocs[sbomConfig.JsonSerializer] = new List<JsonDocument>();
                    }

                    serializersToJsonDocs[sbomConfig.JsonSerializer].Add(generationResult?.Document);
                }
            }

            return new GenerateResult(totalErrors, serializersToJsonDocs);
        }
    }
}
