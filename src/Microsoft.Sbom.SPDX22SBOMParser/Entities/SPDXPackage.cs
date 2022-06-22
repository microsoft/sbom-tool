using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Represents a SPDX 2.2 Package
    /// </summary>
    public class SPDXPackage
    {
        /// <summary>
        /// Name of the package.
        /// </summary>
        [JsonPropertyName("name")]
        public string Name { get; set; }

        /// <summary>
        /// Name of the package.
        /// </summary>
        [JsonPropertyName("packageFileName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string PackageFileName { get; set; }

        /// <summary>
        /// Unique Identifier for elements in SPDX document.
        /// </summary>
        [JsonPropertyName("SPDXID")]
        public string SpdxId { get; set; }

        /// <summary>
        /// The download URL for the exact package, NONE for no download location and NOASSERTION for no attempt.
        /// </summary>
        [JsonPropertyName("downloadLocation")]
        public string DownloadLocation { get; set; }

        /// <summary>
        /// Used to identify specific contents of a package based on actual files that make up each package.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("packageVerificationCode")]
        public PackageVerificationCode PackageVerificationCode { get; set; }

        /// <summary>
        /// If set, specifies if the individual files inside this package were analyzed to capture more data.
        /// </summary>
        [JsonPropertyName("filesAnalyzed")]
        public bool FilesAnalyzed { get; set; }

        /// <summary>
        /// Contain the license the SPDX file creator has concluded as the package or alternative values.
        /// </summary>
        [JsonPropertyName("licenseConcluded")]
        public string LicenseConcluded { get; set; }

        /// <summary>
        /// Contains all license found in the package.
        /// </summary>
        [JsonPropertyName("licenseInfoFromFiles")]
        public List<string> LicenseInfoFromFiles { get; set; }

        /// <summary>
        /// Contains a list of licenses the have been declared by the authors of the package.
        /// </summary>
        [JsonPropertyName("licenseDeclared")]
        public string LicenseDeclared { get; set; }

        /// <summary>
        /// Copyright holder of the package, as well as any dates present.
        /// </summary>
        [JsonPropertyName("copyrightText")]
        public string CopyrightText { get; set; }

        /// <summary>
        /// Version of the package.
        /// Not Required
        /// </summary>
        [JsonPropertyName("versionInfo")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string VersionInfo { get; set; }

        /// <summary>
        /// Provide an independently reproducible mechanism that permits unique identification of a specific 
        /// package that correlates to the data in this SPDX file
        /// </summary>
        [JsonPropertyName("checksums")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<Checksum> Checksums { get; set; }

        /// <summary>
        /// Provide a list of <see cref="ExternalReference"/> that provide additional information or metadata 
        /// about this package.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("externalRefs")]
        public IList<ExternalReference> ExternalReferences { get; set; }
        
        /// <summary>
        /// The name and optional contact information of the person or organization that built this package.
        /// </summary>
        [JsonPropertyName("supplier")]
        public string Supplier { get; set; }

        /// <summary>
        /// The list of file ids that are contained in this package.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("hasFiles")]
        public List<string> HasFiles { get; set; }
    }
}
