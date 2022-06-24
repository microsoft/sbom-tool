﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Ninject;
using Serilog;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    /// <summary>
    /// This class generates an array of filenames and hashes based on the format of the SBOM. 
    /// </summary>
    public class FileArrayGenerator : IJsonArrayGenerator
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

        /// <summary>
        /// Traverses all the files inside the buildDropPath, and serializes the SBOM using the JSON serializer creating
        /// an array object whose key is defined by <paramref name="headerName"/>. Upon failure, returns a list of 
        /// <see cref="FileValidationResult"/> objects that can be used to trace the error.
        /// </summary>
        /// <param name="jsonSerializer">The serializer used to write the SBOM.</param>
        /// <param name="headerName">The header key for the file array object.</param>
        /// <returns></returns>
        public async Task<IList<FileValidationResult>> GenerateAsync()
        {
            using (Recorder.TraceEvent(Events.FilesGeneration))
            {
                IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

                IEnumerable<ISourcesProvider> sourcesProviders = SourcesProviders
                                                    .Where(s => s.IsSupported(ProviderType.Files));

                // Write the start of the array, if supported.
                IList<ISbomConfig> filesArraySupportingSBOMs = new List<ISbomConfig>();
                foreach (var manifestInfo in SBOMConfigs.GetManifestInfos())
                {
                    var config = SBOMConfigs.Get(manifestInfo);

                    if (config.MetadataBuilder.TryGetFilesArrayHeaderName(out string filesArrayHeaderName))
                    {
                        config.JsonSerializer.StartJsonArray(filesArrayHeaderName);
                        filesArraySupportingSBOMs.Add(config);
                    }
                }

                foreach (var sourcesProvider in sourcesProviders)
                {
                    var (jsondDocResults, errors) = sourcesProvider.Get(filesArraySupportingSBOMs);

                    await foreach (JsonDocWithSerializer jsonResults in jsondDocResults.ReadAllAsync())
                    {
                        jsonResults.Serializer.Write(jsonResults.Document);
                    }

                    await foreach (FileValidationResult error in errors.ReadAllAsync())
                    {
                        // TODO fix errors.
                        if (error.ErrorType != ErrorType.ManifestFolder)
                        {
                            totalErrors.Add(error);
                        }
                    }
                }

                // Write the end of the array.
                foreach (ISbomConfig config in filesArraySupportingSBOMs)
                {
                    config.JsonSerializer.EndJsonArray();
                }

                return totalErrors;
            }
        }
    }
}
