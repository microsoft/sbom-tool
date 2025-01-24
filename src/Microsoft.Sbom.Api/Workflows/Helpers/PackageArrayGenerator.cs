// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
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

    private readonly ISbomConfigProvider sbomConfigs;

    private readonly IEnumerable<ISourcesProvider> sourcesProviders;

    private readonly IRecorder recorder;

    public PackageArrayGenerator(
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
        using (recorder.TraceEvent(Events.PackagesGeneration))
        {
            IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

            var sourcesProvider = this.sourcesProviders
                .FirstOrDefault(s => s.IsSupported(ProviderType.Packages));

            // Write the start of the array, if supported.
            IList<ISbomConfig> packagesArraySupportingConfigs = new List<ISbomConfig>();
            foreach (var manifestInfo in sbomConfigs.GetManifestInfos())
            {
                var config = sbomConfigs.Get(manifestInfo);
                if (config.MetadataBuilder.TryGetPackageArrayHeaderName(out var packagesArrayHeaderName))
                {
                    packagesArraySupportingConfigs.Add(config);
                    config.JsonSerializer.StartJsonArray(packagesArrayHeaderName);
                }
            }

            var (jsonDocResults, errors) = sourcesProvider.Get(packagesArraySupportingConfigs);

            // 6. Collect all the json elements and write to the serializer.
            var totalJsonDocumentsWritten = 0;

            await foreach (var jsonDocResult in jsonDocResults.ReadAllAsync())
            {
                jsonDocResult.Serializer.Write(jsonDocResult.Document);
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
                // Write the root package information to the packages array.
                if (sbomConfig.MetadataBuilder.TryGetRootPackageJson(sbomConfigs, out var generationResult))
                {
                    sbomConfig.JsonSerializer.Write(generationResult?.Document);
                    sbomConfig.Recorder.RecordRootPackageId(generationResult?.ResultMetadata?.EntityId);
                    sbomConfig.Recorder.RecordDocumentId(generationResult?.ResultMetadata?.DocumentId);
                }

                // Write the end of the array.
                sbomConfig.JsonSerializer.EndJsonArray();
            }

            return totalErrors;
        }
    }
}
