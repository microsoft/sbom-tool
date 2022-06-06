using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// A structure that represents a package in a SBOM.
    /// </summary>
    public class SBOMPackage
    { 
        /// <summary>
        /// The unique identifier of this package.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// The fully qualified name of this package.
        /// </summary>
        public string PackageName { get; set; }

        /// <summary>
        /// The version of the package.
        /// </summary>
        public string PackageVersion { get; set; }

        /// <summary>
        /// The package url (PURL) for this package. This provides a search string to 
        /// download the package from a given package manager.
        /// </summary>
        public string PackageUrl { get; set; }

        /// <summary>
        /// The source URL where the package was downloaded from.
        /// </summary>
        public string PackageSource { get; set; }


        /// <summary>
        /// Specifies if indiviudal files inside this package were analyzed 
        /// to gather additional data.
        /// </summary>
        public bool FilesAnalyzed { get; set; }

        /// <summary>
        /// The copyright text that was included in the package.
        /// </summary>
        public string CopyrightText { get; set; }

        /// <summary>
        /// A list of the checksums of the current package.
        /// </summary>
        public IEnumerable<Checksum> Checksum { get; set; }

        /// <summary>
        /// The license information included in the package.
        /// </summary>
        public LicenseInfo LicenseInfo { get; set; }

        /// <summary>
        /// The name and contact information of the person or organization that built this package.
        /// </summary>
        public string Supplier { get; set; }

        /// <summary>
        /// Type of the package (e.g npm, git, nuget).
        /// </summary>
        public string Type { get; set; }
    }
}
