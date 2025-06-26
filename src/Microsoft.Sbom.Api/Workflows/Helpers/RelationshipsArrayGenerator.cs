// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Generates an array of relationships between different elements of the SBOM.
/// </summary>
public class RelationshipsArrayGenerator : IJsonArrayGenerator<RelationshipsArrayGenerator>
{
    private readonly RelationshipGenerator generator;

    private readonly ChannelUtils channelUtils;

    private readonly ILogger log;

    private readonly IRecorder recorder;

    public RelationshipsArrayGenerator(
        RelationshipGenerator generator,
        ChannelUtils channelUtils,
        ILogger log,
        IRecorder recorder)
    {
        this.generator = generator;
        this.channelUtils = channelUtils;
        this.log = log;
        this.recorder = recorder;
    }

    public async Task<GeneratorResult> GenerateAsync(IEnumerable<ISbomConfig> targetConfigs, ISet<string> elementsSpdxIdList)
    {
        using (recorder.TraceEvent(Events.RelationshipsGeneration))
        {
            var totalErrors = new List<FileValidationResult>();
            var jsonDocumentCollection = new JsonDocumentCollection<IManifestToolJsonSerializer>();

            IList<ISbomConfig> relationshipsArraySupportingConfigs = new List<ISbomConfig>();
            var jsonArrayStartedForConfig = new Dictionary<ISbomConfig, bool>();

            // Write the relationship array only if supported
            foreach (var sbomConfig in targetConfigs)
            {
                var serializationStrategy = JsonSerializationStrategyFactory.GetStrategy(sbomConfig.ManifestInfo.Version);
                var jsonArrayStarted = serializationStrategy.AddToRelationshipsSupportingConfig(relationshipsArraySupportingConfigs, sbomConfig);
                jsonArrayStartedForConfig[sbomConfig] = jsonArrayStarted;

                if (jsonArrayStarted)
                {
                    var generationData = sbomConfig?.Recorder.GetGenerationData();

                    var jsonChannelsArray = new ChannelReader<JsonDocument>[]
                    {
                    // Packages relationships
                    generator.Run(
                        GetRelationships(
                            RelationshipType.DEPENDS_ON,
                            generationData),
                        sbomConfig.ManifestInfo),

                    // Root package relationship
                    generator.Run(
                        GetRelationships(
                            RelationshipType.DESCRIBES,
                            generationData.DocumentId,
                            [generationData.RootPackageId]),
                        sbomConfig.ManifestInfo),

                    // External reference relationship
                    generator.Run(
                        GetRelationships(
                            RelationshipType.PREREQUISITE_FOR,
                            generationData.RootPackageId,
                            generationData.ExternalDocumentReferenceIDs),
                        sbomConfig.ManifestInfo),

                    // External reference file relationship
                    generator.Run(
                        GetRelationships(
                            RelationshipType.DESCRIBED_BY,
                            generationData.SPDXFileIds,
                            generationData.DocumentId),
                        sbomConfig.ManifestInfo),
                    };

                    // Collect all the json elements and write to the serializer.
                    var count = 0;

                    await foreach (var jsonDoc in channelUtils.Merge(jsonChannelsArray).ReadAllAsync())
                    {
                        count++;
                        jsonDocumentCollection.AddJsonDocument(sbomConfig.JsonSerializer, jsonDoc);
                    }

                    log.Debug("Wrote {Count} relationship elements in the SBOM.", count);
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

    private IEnumerator<Relationship> GetRelationships(RelationshipType relationshipType, GenerationData generationData)
    {
        foreach (var targetElementId in generationData.PackageIds)
        {
            if (targetElementId.Key != null || generationData.RootPackageId != null)
            {
                yield return new Relationship
                {
                    RelationshipType = relationshipType,
                    TargetElementId = targetElementId.Key,
                    SourceElementId = targetElementId.Value ?? generationData.RootPackageId
                };
            }
        }
    }

    private IEnumerator<Relationship> GetRelationships(RelationshipType relationshipType, string sourceElementId, IEnumerable<string> targetElementIds)
    {
        foreach (var targetElementId in targetElementIds)
        {
            if (targetElementId != null || sourceElementId != null)
            {
                yield return new Relationship
                {
                    RelationshipType = relationshipType,
                    TargetElementId = targetElementId,
                    SourceElementId = sourceElementId
                };
            }
        }
    }

    private IEnumerator<Relationship> GetRelationships(RelationshipType relationshipType, IList<string> sourceElementIds, string targetElementId)
    {
        foreach (var sourceElementId in sourceElementIds)
        {
            if (sourceElementId != null || targetElementId != null)
            {
                yield return new Relationship
                {
                    RelationshipType = relationshipType,
                    SourceElementId = sourceElementId,
                    TargetElementId = targetElementId,
                };
            }
        }
    }

    private IEnumerator<Relationship> GetRelationships(RelationshipType relationshipType, string sourceElementId, IEnumerable<KeyValuePair<string, string>> targetElementIds)
    {
        foreach (var targetElementId in targetElementIds)
        {
            if (sourceElementId != null || targetElementId.Key != null || targetElementId.Value != null)
            {
                yield return new Relationship
                {
                    RelationshipType = relationshipType,
                    TargetElementId = targetElementId.Value,
                    TargetElementExternalReferenceId = targetElementId.Key,
                    SourceElementId = sourceElementId
                };
            }
        }
    }
}
