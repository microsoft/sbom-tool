// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Tool;
using PowerArgs;

public class GenerateSbomTask : Task
{
    // TODO it is possible we will want to expose additional arguments, either as required or optional.
    // Will need to get SDK team/ windows team input on which arguments are necessary.

    /// <summary>
    /// The path to the drop directory for which the SBOM will be generated
    /// </summary>
    [Required]
    public string BuildDropPath { get; set; }

    /// <summary>
    /// The path to the directory containing build components and package information.
    /// For example, path to a .csproj or packages.config file.
    /// </summary>
    [Required]
    public string BuildComponentPath { get; set; }

    /// <summary>
    /// Supplier of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageSupplier { get; set; }

    /// <summary>
    /// Name of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageName { get; set; }

    /// <summary>
    /// Version of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageVersion { get; set; }

    /// <summary>
    /// The base path of the SBOM namespace uri.
    /// </summary>
    [Required]
    public string NamespaceBaseUri { get; set; }

    /// <summary>
    /// A unique URI part that will be appended to NamespaceBaseUri.
    /// </summary>
    public string NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// The path to a file containing a list of external SBOMs that will be appended to the
    /// SBOM that is being generated.
    /// </summary>
    public string ExternalDocumentListFile { get; set; }

    /// <summary>
    /// If true, it will fetch licensing information for detected packages.
    /// </summary>
    public bool FetchLicenseInformation { get; set; }

    /// <summary>
    /// If true, it will parse licensing and supplier information from a packages metadata file.
    /// </summary>
    public bool EnablePackageMetadataParsing { get; set; }

    /// <summary>
    /// Determines how detailed the outputed logging will be.
    /// </summary>
    public string Verbosity { get; set; }

    /// <summary>
    /// A list of the name and version of the manifest format being used.
    /// </summary>
    public string ManifestInfo { get; set; }

    /// <summary>
    /// If true, it will delete the previously generated SBOM manifest directory before
    /// generating a new SBOM in ManifestDirPath.
    /// </summary>
    public bool DeleteManifestDirIfPresent { get; set; }

    /// <summary>
    /// The path where the SBOM will be generated.
    /// </summary>
    public string ManifestDirPath { get; set; }

    [Output]
    public string SbomPath { get; set; }

    public override bool Execute()
    {
        if (string.IsNullOrEmpty(BuildDropPath) ||
            string.IsNullOrEmpty(BuildComponentPath) ||
            string.IsNullOrEmpty(PackageSupplier) ||
            string.IsNullOrEmpty(PackageName) ||
            string.IsNullOrEmpty(PackageVersion))
        {
            Log.LogError("Required argument not provided.");
            return false;
        }

        try
        {
            // TODO replace this with a call to SBOM API to generate SBOM
            SbomPath = "path/to/sbom";
            return true;
        }
        catch (Exception e)
        {
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }
}
