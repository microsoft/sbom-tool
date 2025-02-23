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
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// This class generates an array of filenames and hashes based on the format of the SBOM.
/// </summary>
public class FileArrayGenerator : IJsonArrayGenerator<FileArrayGenerator>
{
    private readonly IEnumerable<ISourcesProvider> sourcesProviders;

    private readonly IRecorder recorder;

    private readonly ILogger logger;

    public ISbomConfig SbomConfig { get; set; }

    public string SpdxManifestVersion { get; set; }

    public FileArrayGenerator(
        IEnumerable<ISourcesProvider> sourcesProviders,
        IRecorder recorder,
        ILogger logger)
    {
        this.sourcesProviders = sourcesProviders ?? throw new ArgumentNullException(nameof(sourcesProviders));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Traverses all the files inside the buildDropPath, and serializes the SBOM using the JSON serializer creating
    /// an array object whose key is defined by <paramref name="headerName"/>. Upon failure, returns a list of
    /// <see cref="FileValidationResult"/> objects that can be used to trace the error.
    /// </summary>
    /// <param name="jsonSerializer">The serializer used to write the SBOM.</param>
    /// <param name="headerName">The header key for the file array object.</param>
    /// <returns></returns>
    public async Task<GenerationResult> GenerateAsync()
    {
        using (recorder.TraceEvent(Events.FilesGeneration))
        {
            var totalErrors = new List<FileValidationResult>();

            var sourcesProviders = this.sourcesProviders
                .Where(s => s.IsSupported(ProviderType.Files));

            // Write the start of the array, if supported.
            IList<ISbomConfig> filesArraySupportingSboms = new List<ISbomConfig>();
            var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(SpdxManifestVersion);
            serializationStrategy.AddToFilesSupportingConfig(filesArraySupportingSBOMs, this.SbomConfig);

            this.logger.Verbose("Started writing files array for {configFile}.", this.SbomConfig.ManifestJsonFilePath);

            var jsonDocumentCollection = new JsonDocumentCollection<IManifestToolJsonSerializer>();
            foreach (var sourcesProvider in sourcesProviders)
            {
                var (jsondDocResults, errors) = sourcesProvider.Get(filesArraySupportingSboms);

                await foreach (var jsonResults in jsondDocResults.ReadAllAsync())
                {
                    jsonDocumentCollection.AddJsonDocument(jsonResults.Serializer, jsonResults.Document);
                }

                await foreach (var error in errors.ReadAllAsync())
                {
                    // TODO fix errors.
                    if (error.ErrorType != ErrorType.ManifestFolder)
                    {
                        totalErrors.Add(error);
                    }
                }
            }

            return new GenerationResult(totalErrors, jsonDocumentCollection.SerializersToJson);
        }
    }
}
