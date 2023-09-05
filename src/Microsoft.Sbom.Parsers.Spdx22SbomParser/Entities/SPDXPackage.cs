// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

/// <summary>
/// Represents a SPDX 2.2 Package.
/// </summary>
public class SPDXPackage
{
    /// <summary>
    /// Gets or sets name of the package.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets name of the package.
    /// </summary>
    [JsonPropertyName("packageFileName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string PackageFileName { get; set; }

    /// <summary>
    /// Gets or sets unique Identifier for elements in SPDX document.
    /// </summary>
    [JsonPropertyName("SPDXID")]
    public string SpdxId { get; set; }

    /// <summary>
    /// Gets or sets the download URL for the exact package, NONE for no download location and NOASSERTION for no attempt.
    /// </summary>
    [JsonPropertyName("downloadLocation")]
    public string DownloadLocation { get; set; }

    /// <summary>
    /// Gets or sets used to identify specific contents of a package based on actual files that make up each package.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("packageVerificationCode")]
    public PackageVerificationCode PackageVerificationCode { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether if set, specifies if the individual files inside this package were analyzed to capture more data.
    /// </summary>
    [JsonPropertyName("filesAnalyzed")]
    public bool FilesAnalyzed { get; set; }

    /// <summary>
    /// Gets or sets contain the license the SPDX file creator has concluded as the package or alternative values.
    /// </summary>
    [JsonPropertyName("licenseConcluded")]
    public string LicenseConcluded { get; set; }

    /// <summary>
    /// Gets or sets contains all license found in the package.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("licenseInfoFromFiles")]
    public IEnumerable<string> LicenseInfoFromFiles { get; set; }

    /// <summary>
    /// Gets or sets contains a list of licenses the have been declared by the authors of the package.
    /// </summary>
    [JsonPropertyName("licenseDeclared")]
    public string LicenseDeclared { get; set; }

    /// <summary>
    /// Gets or sets copyright holder of the package, as well as any dates present.
    /// </summary>
    [JsonPropertyName("copyrightText")]
    public string CopyrightText { get; set; }

    /// <summary>
    /// Gets or sets version of the package.
    /// Not Required.
    /// </summary>
    [JsonPropertyName("versionInfo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string VersionInfo { get; set; }

    /// <summary>
    /// Gets or sets provide an independently reproducible mechanism that permits unique identification of a specific
    /// package that correlates to the data in this SPDX file.
    /// </summary>
    [JsonPropertyName("checksums")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<Checksum> Checksums { get; set; }

    /// <summary>
    /// Gets or sets provide a list of <see cref="ExternalReference"/> that provide additional information or metadata
    /// about this package.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("externalRefs")]
    public IList<ExternalReference> ExternalReferences { get; set; }

    /// <summary>
    /// Gets or sets the name and optional contact information of the person or organization that built this package.
    /// </summary>
    [JsonPropertyName("supplier")]
    public string Supplier { get; set; }

    /// <summary>
    /// Gets or sets the list of file ids that are contained in this package.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("hasFiles")]
    public List<string> HasFiles { get; set; }
}
