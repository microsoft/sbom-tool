// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Ninject;
using Serilog;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    /// <summary>
    /// Generates an array of relationships between different elements of the SBOM.
    /// </summary>
    public class RelationshipsArrayGenerator : IJsonArrayGenerator
    {
        [Inject]
        public RelationshipGenerator Generator { get; set; }

        [Inject]
        public ChannelUtils ChannelUtils { get; set; }

        [Inject]
        public ILogger Log { get; set; }

        [Inject]
        public ISbomConfigProvider SbomConfigs { get; set; }

        [Inject]
        public IRecorder Recorder { get; set; }

        public async Task<IList<FileValidationResult>> GenerateAsync()
        {
            using (Recorder.TraceEvent(Events.RelationshipsGeneration))
            {
                IList<FileValidationResult> totalErrors = new List<FileValidationResult>();

                // Write the relationship array only if supported
                foreach (var manifestInfo in SbomConfigs.GetManifestInfos())
                {
                    var sbomConfig = SbomConfigs.Get(manifestInfo);
                    if (sbomConfig.MetadataBuilder.TryGetRelationshipsHeaderName(out string relationshipArrayHeaderName))
                    {
                        sbomConfig.JsonSerializer.StartJsonArray(relationshipArrayHeaderName);

                        // Get generation data
                        var generationData = sbomConfig.Recorder.GetGenerationData();

                        var jsonChannelsArray = new ChannelReader<JsonDocument>[]
                        {
                            // Packages relationships
                            Generator.Run(
                                GetRelationships(
                                RelationshipType.DEPENDS_ON,
                                generationData.RootPackageId,
                                generationData.PackageIds),
                                sbomConfig.ManifestInfo),

                            // Root package relationship
                            Generator.Run(
                                GetRelationships(
                                RelationshipType.DESCRIBES,
                                generationData.DocumentId,
                                new string[] { generationData.RootPackageId }),
                                sbomConfig.ManifestInfo),

                            // External reference relationship
                            Generator.Run(
                                GetRelationships(
                                RelationshipType.PREREQUISITE_FOR,
                                generationData.RootPackageId,
                                generationData.ExternalDocumentReferenceIDs),
                                sbomConfig.ManifestInfo),

                            // External reference file relationship
                            Generator.Run(
                                GetRelationships(
                                RelationshipType.DESCRIBED_BY,
                                generationData.SPDXFileIds,
                                generationData.DocumentId),
                                sbomConfig.ManifestInfo),
                        };

                        // Collect all the json elements and write to the serializer.
                        int count = 0;

                        await foreach (JsonDocument jsonDoc in ChannelUtils.Merge(jsonChannelsArray).ReadAllAsync())
                        {
                            count++;
                            sbomConfig.JsonSerializer.Write(jsonDoc);
                        }

                        Log.Debug($"Wrote {count} relationship elements in the SBOM.");

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
}
