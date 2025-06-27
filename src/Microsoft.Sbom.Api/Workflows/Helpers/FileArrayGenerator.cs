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
    /// an array object. Upon failure, returns a list of
    /// <see cref="GenerationResult"/> objects that can be used to trace the error.
    /// </summary>
    public async Task<GeneratorResult> GenerateAsync(IEnumerable<ISbomConfig> targetConfigs, ISet<string> elementsSpdxIdList)
    {
        using (recorder.TraceEvent(Events.FilesGeneration))
        {
            var totalErrors = new List<FileValidationResult>();

            // Write the start of the array, if supported.
            IList<ISbomConfig> filesArraySupportingSboms = new List<ISbomConfig>();
            var jsonArrayStartedForConfig = new Dictionary<ISbomConfig, bool>();
            var filesSourcesProviders = this.sourcesProviders
               .Where(s => s.IsSupported(ProviderType.Files));

            foreach (var config in targetConfigs)
            {
                var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(config.ManifestInfo.Version);
                var jsonArrayStarted = serializationStrategy.AddToFilesSupportingConfig(filesArraySupportingSboms, config);
                jsonArrayStartedForConfig[config] = jsonArrayStarted;
                this.logger.Verbose("Started writing files for {configFile}.", config.ManifestJsonFilePath);
            }

            var jsonDocumentCollection = new JsonDocumentCollection<IManifestToolJsonSerializer>();
            foreach (var sourcesProvider in filesSourcesProviders)
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

            var generatorResult = new GeneratorResult(totalErrors, jsonDocumentCollection.SerializersToJson, jsonArrayStartedForConfig);

            foreach (var config in targetConfigs)
            {
                var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(config.ManifestInfo.Version);
                serializationStrategy.WriteJsonObjectsToManifest(generatorResult, config, elementsSpdxIdList);
            }

            jsonDocumentCollection.DisposeAllJsonDocuments();

            return generatorResult;
        }
    }
}
