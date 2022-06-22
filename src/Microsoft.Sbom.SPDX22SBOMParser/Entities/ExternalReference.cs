using Microsoft.SPDX22SBOMParser.Entities.Enums;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Defines a reference to an external source of additional information, metadata,
    /// enumerations, asset identifiers, or downloadable content believed to be 
    /// relevant to a Package.
    /// </summary>
    public class ExternalReference
    {
        /// <summary>
        /// The category for the external reference.
        /// </summary>
        [JsonPropertyName("referenceCategory")]
        public ReferenceCategory ReferenceCategory { get; set; }

        /// <summary>
        /// Type of the external reference. These are definined in an appendix in the SPDX specification.
        /// https://spdx.github.io/spdx-spec/appendix-VI-external-repository-identifiers/
        /// </summary>
        [JsonPropertyName("referenceType")]
        public ExternalRepositoryType Type { get; set; }

        /// <summary>
        /// A unique string without any spaces that specifies a location where the package specific information
        /// can be located. The locator constraints are defined by the <see cref="Type"/>
        /// </summary>
        [JsonPropertyName("referenceLocator")]
        public string Locator { get; set; }
    }
}
