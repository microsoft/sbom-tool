// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// A structure that represents a package in a SBOM.
/// </summary>
public class SbomPackage
{
    /// <summary>
    /// Gets or sets the unique identifier of this package.
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// Gets or sets the fully qualified name of this package.
    /// </summary>
    public string PackageName { get; set; }

    /// <summary>
    /// Gets or sets the version of the package.
    /// </summary>
    public string PackageVersion { get; set; }

    /// <summary>
    /// Gets or sets the package url (PURL) for this package. This provides a search string to
    /// download the package from a given package manager.
    /// </summary>
    public string PackageUrl { get; set; }

    /// <summary>
    /// Gets or sets the source URL where the package was downloaded from.
    /// </summary>
    public string PackageSource { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether specifies if indiviudal files inside this package were analyzed
    /// to gather additional data.
    /// </summary>
    public bool FilesAnalyzed { get; set; }

    /// <summary>
    /// Gets or sets the copyright text that was included in the package.
    /// </summary>
    public string CopyrightText { get; set; }

    /// <summary>
    /// Gets or sets a list of the checksums of the current package.
    /// </summary>
    public IEnumerable<Checksum> Checksum { get; set; }

    /// <summary>
    /// Gets or sets the license information included in the package.
    /// </summary>
    public LicenseInfo LicenseInfo { get; set; }

    /// <summary>
    /// Gets or sets the name and contact information of the person or organization that built this package.
    /// </summary>
    public string Supplier { get; set; }

    /// <summary>
    /// Gets or sets type of the package (e.g npm, git, nuget).
    /// </summary>
    public string Type { get; set; }

    /// <summary>
    /// Get or set unique identifier (Id) of DependOn package
    /// </summary>
    public string DependOn { get; set; }
}
