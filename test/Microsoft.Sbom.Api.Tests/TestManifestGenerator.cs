using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Microsoft.Sbom.Api.Tests
{
    class TestManifestGenerator : IManifestGenerator
    {
        public AlgorithmName[] RequiredHashAlgorithms => new[] {
            AlgorithmName.SHA256
        };

        public string Version { get; set; } = "1.0.0";

        public IList<string> HeaderKeys => throw new NotImplementedException();

        public string FilesArrayHeaderName => "Outputs";

        public string PackagesArrayHeaderName => "Packages";

        public string RelationshipsArrayHeaderName => "Relationships";

        public string ExternalDocumentRefArrayHeaderName => "externalDocumentRefs";

        public GenerationResult GenerateJsonDocument(InternalSBOMFileInfo fileInfo)
        {
            if (fileInfo is null)
            {
                throw new ArgumentNullException(nameof(fileInfo));
            }

            if (fileInfo.Checksum == null || fileInfo.Checksum.Count() == 0)
            {
                throw new ArgumentException(nameof(fileInfo.Checksum));
            }

            if (string.IsNullOrWhiteSpace(fileInfo.Path))
            {
                throw new ArgumentException(nameof(fileInfo.Path));
            }

            var jsonString = $@"
{{
    ""Source"":""{fileInfo.Path}"",
    ""Sha256Hash"":""{fileInfo.Checksum.Where(h => h.Algorithm == AlgorithmName.SHA256).Select(h => h.ChecksumValue).FirstOrDefault()}""
}}
";

            return new GenerationResult
            {
                Document = JsonDocument.Parse(jsonString),
                ResultMetadata = new ResultMetadata
                {
                    EntityId = $"{fileInfo.Path}_{Guid.NewGuid()}"
                }
            };
        }

        public GenerationResult GenerateJsonDocument(SBOMPackage packageInfo)
        {
            var jsonString = $@"
{{
    ""Name"": ""{packageInfo.PackageName}""
}}
";

            return new GenerationResult
            {
                Document = JsonDocument.Parse(jsonString),
                ResultMetadata = new ResultMetadata
                {
                    EntityId = $"{packageInfo.PackageName}_{Guid.NewGuid()}"
                }
            };
        }

        public GenerationResult GenerateJsonDocument(Relationship relationship)
        {
            return new GenerationResult
            {
                Document = JsonDocument.Parse(JsonSerializer.Serialize(relationship))
            };
        }

        public GenerationResult GenerateJsonDocument(ExternalDocumentReferenceInfo externalDocumentReferenceInfo)
        {
            var jsonString = $@"
            {{
                ""ExternalDocumentId"":""{externalDocumentReferenceInfo.ExternalDocumentName}"",
                ""SpdxDocument"":""{externalDocumentReferenceInfo.DocumentNamespace}""
            }}
            ";

            return new GenerationResult
            {
                Document = JsonDocument.Parse(jsonString),
                ResultMetadata = new ResultMetadata
                {
                    EntityId = $"{externalDocumentReferenceInfo.ExternalDocumentName}_{Guid.NewGuid()}"
                }
            };
        }

        public GenerationResult GenerateRootPackage(IInternalMetadataProvider _)
        {
            var jsonString = $@"
{{
    ""Name"": ""rootPackage""
}}
";

            return new GenerationResult
            {
                Document = JsonDocument.Parse(jsonString),
                ResultMetadata = new ResultMetadata
                {
                    DocumentId = "doc-rootPackage-Id",
                    EntityId = "rootPackage-Id"
                }
            };
        }

        public IDictionary<string, object> GetMetadataDictionary(IInternalMetadataProvider internalMetadataProvider)
        {
            return new Dictionary<string, object>
            {
                { "Version", "1.0.0" },
                { "Build", internalMetadataProvider.GetMetadata(MetadataKey.Build_BuildId) },
                { "Definition", internalMetadataProvider.GetMetadata(MetadataKey.Build_DefinitionName) },
            };
        }

        public ManifestInfo RegisterManifest()
        {
            return new ManifestInfo
            {
                Name = "TestManifest",
                Version = "1.0.0"
            };
        }
    }
}
