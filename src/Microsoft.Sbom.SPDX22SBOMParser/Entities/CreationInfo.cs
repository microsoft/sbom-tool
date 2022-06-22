using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Used to define creation information about the SBOM.
    /// </summary>
    public class CreationInfo
    {
        /// <summary>
        /// A string that specifies the time the SBOM was created on.
        /// </summary>
        [JsonPropertyName("created")]
        public string Created { get; set; }
        
        /// <summary>
        /// A list of strings that specify metadata about the creators of this
        /// SBOM. This could be the person or organization name, or tool name, etc.
        /// </summary>
        [JsonPropertyName("creators")]
        public List<string> Creators { get; set; }
    }
}
