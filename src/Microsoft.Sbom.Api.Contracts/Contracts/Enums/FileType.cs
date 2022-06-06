using System.Runtime.Serialization;

namespace Microsoft.Sbom.Contracts.Enums
{
    /// <summary>
    /// Represents the type of a file.
    /// </summary>
    public enum FileType
    {
        /// <summary>
        /// The file is an SPDX type.
        /// </summary>
        [EnumMember(Value = "SPDX")]
        SPDX = 0,
    }
}
