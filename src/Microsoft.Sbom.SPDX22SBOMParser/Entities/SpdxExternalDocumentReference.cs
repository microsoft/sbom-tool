using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// SPDX 2.2 format External Document reference
    /// </summary>
    public class SpdxExternalDocumentReference
    {
        /// <summary>
        /// Unique Identifier for ExternalDocumentReference in SPDX document.
        /// </summary>
        [JsonPropertyName("externalDocumentId")]
        public string ExternalDocumentId { get; set; }

        /// <summary>
        /// Document namespace of the input SBOM
        /// </summary>
        [JsonPropertyName("spdxDocument")]
        public string SpdxDocument { get; set; }

        /// <summary>
        /// Checksum values for External SBOM file
        /// </summary>
        [JsonPropertyName("checksum")]
        public Checksum Checksum { get; set; }
    }
}
