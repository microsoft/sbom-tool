// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Generates an array of relationships between different elements of the SBOM.
/// </summary>
public class RelationshipsArrayGenerator : IJsonArrayGenerator<RelationshipsArrayGenerator>
{
    private readonly RelationshipGenerator generator;

    private readonly ChannelUtils channelUtils;

    private readonly ILogger<RelationshipsArrayGenerator> log;

    private readonly ISbomConfigProvider sbomConfigs;

    private readonly IRecorder recorder;

    public RelationshipsArrayGenerator(
        RelationshipGenerator generator,
        ChannelUtils channelUtils,
        ILogger<RelationshipsArrayGenerator> log,
        ISbomConfigProvider sbomConfigs,
        IRecorder recorder)
    {
        this.generator = generator;
        this.channelUtils = channelUtils;
        this.log = log;
        this.sbomConfigs = sbomConfigs;
        this.recorder = recorder;
    }

    public async Task<IList<FileValidationResult>> GenerateAsync()
    {
        using (recorder.TraceEvent(Events.RelationshipsGeneration))
        {
            IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

            // Write the relationship array only if supported
            foreach (var manifestInfo in sbomConfigs.GetManifestInfos())
            {
                var sbomConfig = sbomConfigs.Get(manifestInfo);
                if (sbomConfig.MetadataBuilder.TryGetRelationshipsHeaderName(out var relationshipArrayHeaderName))
                {
                    sbomConfig.JsonSerializer.StartJsonArray(relationshipArrayHeaderName);

                    // Get generation data
                    var generationData = sbomConfig.Recorder.GetGenerationData();

                    var jsonChannelsArray = new ChannelReader<JsonDocument>[]
                    {
                        // Packages relationships
                        generator.Run(
                            GetRelationships(
                                RelationshipType.DEPENDS_ON,
                                generationData.RootPackageId,
                                generationData.PackageIds),
                            sbomConfig.ManifestInfo),

                        // Root package relationship
                        generator.Run(
                            GetRelationships(
                                RelationshipType.DESCRIBES,
                                generationData.DocumentId,
                                new string[] { generationData.RootPackageId }),
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
                        sbomConfig.JsonSerializer.Write(jsonDoc);
                    }

                    log.LogDebug($"Wrote {count} relationship elements in the SBOM.");

                    // Write the end of the array.
                    sbomConfig.JsonSerializer.EndJsonArray();
                }
            }

            return totalErrors;
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
