using System.Runtime.Serialization;

namespace Microsoft.Sbom.Contracts.Enums
{
    /// <summary>
    /// Represents an entity in a SBOM, like a package or file.
    /// </summary>
    public enum EntityType
    {
        /// <summary>
        /// The entity is unknown.
        /// </summary>
        [EnumMember(Value = "Unknown")]
        Unknown = 0,

        /// <summary>
        /// The entity is a file.
        /// </summary>
        [EnumMember(Value = "File")]
        File = 1,

        /// <summary>
        /// The entity is a package.
        /// </summary>
        [EnumMember(Value = "Package")]
        Package = 2
    }
}
