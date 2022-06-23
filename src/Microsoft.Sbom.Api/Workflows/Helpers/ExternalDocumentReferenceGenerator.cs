﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Utils;
using Ninject;
using Serilog;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    /// <summary>
    /// This class generates an array of external document references. 
    /// </summary>
    public class ExternalDocumentReferenceGenerator : IJsonArrayGenerator
    {
        [Inject]
        public IConfiguration Configuration { get; set; }

        [Inject]
        public ILogger Log { get; set; }

        [Inject]
        public ISbomConfigProvider SBOMConfigs { get; set; }

        [Inject]
        public IList<ISourcesProvider> SourcesProviders { get; set; }

        [Inject]
        public IRecorder Recorder { get; set; }

        public async Task<IList<FileValidationResult>> GenerateAsync()
        {
            using (Recorder.TraceEvent(Events.ExternalDocumentReferenceGeneration))
            {
                IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

                IEnumerable<ISourcesProvider> sourcesProviders = SourcesProviders
                                                    .Where(s => s.IsSupported(ProviderType.ExternalDocumentReference));
                if (!sourcesProviders.Any())
                {
                    Log.Debug($"No source providers found for {ProviderType.ExternalDocumentReference}");
                    return totalErrors;
                }

                // Write the start of the array, if supported.
                IList<ISbomConfig> externalRefArraySupportingConfigs = new List<ISbomConfig>();
                foreach (var manifestInfo in SBOMConfigs.GetManifestInfos())
                {
                    var config = SBOMConfigs.Get(manifestInfo);
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
}
