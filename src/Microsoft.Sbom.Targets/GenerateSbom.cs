// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using Microsoft.Build.Framework;

/// <summary>
/// This partial class defines and sanitizes the arguments that will be passed
/// into the SBOM API and CLI tool for generation.
/// </summary>
public partial class GenerateSbom
{
    /// <summary>
    /// Gets or sets the path to the drop directory for which the SBOM will be generated.
    /// </summary>
    [Required]
    public string BuildDropPath { get; set; }

    /// <summary>
    /// Gets or sets the supplier of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageSupplier { get; set; }

    /// <summary>
    /// Gets or sets the name of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageName { get; set; }

    /// <summary>
    /// Gets or sets the version of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageVersion { get; set; }

    /// <summary>
    /// Gets or sets the base path of the SBOM namespace uri.
    /// </summary>
    [Required]
    public string NamespaceBaseUri { get; set; }

    /// <summary>
    /// Gets or sets the path to the directory containing build components and package information.
    /// For example, path to a .csproj or packages.config file.
    /// </summary>
    public string BuildComponentPath { get; set; }

    /// <summary>
    /// Gets or sets a unique URI part that will be appended to NamespaceBaseUri.
    /// </summary>
    public string NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// Gets or sets the path to a file containing a list of external SBOMs that will be appended to the
    /// SBOM that is being generated.
    /// </summary>
    public string ExternalDocumentListFile { get; set; }

    /// <summary>
    /// Indicates whether licensing information will be fetched for detected packages.
    /// </summary>
    public bool FetchLicenseInformation { get; set; }

    /// <summary>
    /// Indicates whether to parse licensing and supplier information from a packages metadata file.
    /// </summary>
    public bool EnablePackageMetadataParsing { get; set; }

    /// <summary>
    /// Gets or sets the verbosity level for logging output.
    /// </summary>
    public string Verbosity { get; set; }

    /// <summary>
    /// Gets or sets a list of names and versions of the manifest format being used.
    /// </summary>
    public string ManifestInfo { get; set; }

    /// <summary>
    /// Indicates whether the previously generated SBOM manifest directory should be deleted
    /// before generating a new SBOM in the directory specified by ManifestDirPath.
    /// Defaults to true.
    /// </summary>
    public bool DeleteManifestDirIfPresent { get; set; } = true;

    /// <summary>
    /// Gets or sets the path where the SBOM will be generated. For now, this property
    /// will be unset as the _manifest directory is intended to be at the root of a NuGet package
    /// specified by BuildDropPath.
    /// </summary>
    public string ManifestDirPath { get; set; }

    /// <summary>
    /// Gets or sets the path to the SBOM CLI tool
    /// </summary>
    public string SbomToolPath { get; set; }
}
