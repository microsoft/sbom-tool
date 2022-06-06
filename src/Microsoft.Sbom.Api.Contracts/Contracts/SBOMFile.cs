using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Customer facing structure that represents a file in a SBOM.
    /// </summary>
    public class SBOMFile
    {
        /// <summary>
        /// A list of the checksums for the file.
        /// </summary>
        public IEnumerable<Checksum> Checksum { get; set; }

        /// <summary>
        /// Copyright holder of the file, as well as any dates present.
        /// </summary>
        public string FileCopyrightText { get; set; }

        /// <summary>
        /// Contain the license the file creator has concluded or alternative values.
        /// </summary>
        public string LicenseConcluded { get; set; }

        /// <summary>
        /// Contains any license information actually found in the file. 
        /// </summary>
        public List<string> LicenseInfoInFiles { get; set; }

        /// <summary>
        /// The relative path to the BuildDropPath of the file in the SBOM.
        /// </summary>
        public string Path { get; set; }
    }
}
