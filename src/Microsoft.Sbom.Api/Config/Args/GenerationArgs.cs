// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// The command line arguments provided for the generate action in ManifestTool.
/// </summary>
public class GenerationArgs : CommonArgs
{
    /// <summary>
    /// Gets or sets the root folder of the drop directory for which the SBOM file will be generated.
    /// </summary>
    [ArgShortcut("b")]
    [ArgDescription("The root folder of the drop directory for which the SBOM file will be generated.")]
    public string BuildDropPath { get; set; }

    /// <summary>
    /// Gets or sets the folder containing the build components and packages.
    /// </summary>
    [ArgShortcut("bc")]
    [ArgDescription("The folder containing the build components and packages.")]
    public string BuildComponentPath { get; set; }

    /// <summary>
    /// Gets or sets the file path containing a list of files for which the manifest file will be generated.
    /// List file is an unordered set of files formated as one file per line separated
    /// by Environment.NewLine. Blank lines are discarded.
    /// </summary>
    [ArgShortcut("bl")]
    [ArgDescription("The file path to a file containing a list of files one file per line for which the SBOM" +
                    " file will be generated. Only files listed in the file will be inlcuded in the generated SBOM.")]
    public string BuildListFile { get; set; }

    /// <summary>
    /// Gets or sets the root folder where the generated manifest files as well as other files will be placed.
    /// By default we will generate this folder in the same level as the build drop with the name '_manifest'.
    /// </summary>
    [ArgShortcut("m")]
    [ArgDescription("The path of the directory where the generated SBOM files will be placed." +
                    " A folder named '_manifest' will be created at this location, where all generated SBOMs will be placed." +
                    " If this parameter is not specified, the files will be placed in {BuildDropPath}/_manifest directory.")]
    public string ManifestDirPath { get; set; }

    /// <summary>
    /// Gets or sets the name of the package this SBOM represents.
    /// </summary>
    [ArgShortcut("pn")]
    [ArgDescription("The name of the package this SBOM represents. If this is not provided, we will try to infer this " +
                    "name from the build that generated this package, if that also fails, the SBOM generation fails.")]
    public string PackageName { get; set; }

    [ArgShortcut("pv")]
    [ArgDescription("The version of the package this SBOM represents. If this is not provided, we will " +
                    "try to infer the version from the build that generated this package, if that also fails, the " +
                    "SBOM generation fails.")]
    public string PackageVersion { get; set; }

    [ArgShortcut("ps")]
    [ArgDescription("Supplier of the package that this SBOM represents.")]
    public string PackageSupplier { get; set; }

    [ArgDescription("Comma separated list of docker image names or hashes to be scanned for packages, ex: ubuntu:16.04, 56bab49eef2ef07505f6a1b0d5bd3a601dfc3c76ad4460f24c91d6fa298369ab.")]
    [ArgShortcut("di")]
    public string DockerImagesToScan { get; set; }

    [ArgShortcut("cd")]
    [ArgDescription("Additional set of arguments for Component Detector.  An appropriate usage of this would be a space-delimited list of `--key value` pairs, respresenting command-line switches.")]
    public string AdditionalComponentDetectorArgs { get; set; }

    /// <summary>
    /// Gets or sets the path to a file containing a list of external SBOMs that will be included as external document reference in the output SBOM.
    /// </summary>
    [ArgShortcut("er")]
    [ArgDescription("The path to a file containing a list of external SBOMs that will be included as external document reference in the output SBOM. SPDX 2.2 is the only supported format for now.")]
    public string ExternalDocumentReferenceListFile { get; set; }

    /// <summary>
    /// Gets or sets unique part of the namespace uri for SPDX 2.2 SBOMs. This value should be globally unique.
    /// If this value is not provided, we generate a unique guid that will make the namespace globally unique.
    /// </summary>
    [ArgShortcut("nsu")]
    [ArgDescription("A unique valid URI part that will be appended to the SPDX SBOM namespace URI. This value should be globally unique.")]
    public string NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// Gets or sets the base of the URI that will be used to generate this SBOM. This should be a value that identifies that
    /// the SBOM belongs to a single publisher (or company).
    /// </summary>
    [ArgShortcut("nsb")]
    [ArgDescription("The base path of the SBOM namespace URI.")]
    public string NamespaceUriBase { get; set; }

    /// <summary>
    /// Gets or sets a timestamp in the format. <code>yyyy-MM-ddTHH:mm:ssZ</code> that will be used as the generated timestamp for the SBOM.
    /// </summary>
    [ArgShortcut("gt")]
    [ArgDescription("A timestamp in the format 'yyyy-MM-ddTHH:mm:ssZ' that will be used as the generated timestamp for the SBOM.")]
    public string GenerationTimestamp { get; set; }

    /// <summary>
    /// If set to true, we will delete any previous manifest directories that are already present in the ManifestDirPath without asking the user
    /// for confirmation. The new manifest directory will then be created at this location and the generated SBOM will be stored there.
    /// </summary>
    [ArgDescription("If set to true, we will delete any previous manifest directories that are already present in the ManifestDirPath without " +
                    "asking the user for confirmation. The new manifest directory will then be created at this location and the generated SBOM " +
                    "will be stored there.")]
    public bool? DeleteManifestDirIfPresent { get; set; }

    /// <summary>
    /// If set to true, we will attempt to fetch license information of packages detected in the SBOM from the ClearlyDefinedApi.
    /// </summary>
    [ArgShortcut("li")]
    [ArgDescription("If set to true, we will attempt to fetch license information of packages detected in the SBOM from the ClearlyDefinedApi.")]
    public bool FetchLicenseInformation { get; set; }
}
