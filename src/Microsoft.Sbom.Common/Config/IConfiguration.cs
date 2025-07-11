// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Serilog.Events;

namespace Microsoft.Sbom.Common.Config;

/// <summary>
/// This holds the configuration for the ManifestTool. The values in this
/// file are populated from the command line or config file. Some values
/// are set by default.
/// </summary>
public interface IConfiguration
{
    /// <summary>
    /// Gets or sets the root folder of the drop directory to validate or generate.
    /// </summary>
    public ConfigurationSetting<string> BuildDropPath { get; set; }

    /// <summary>
    /// Gets or sets the folder containing the build components and packages.
    /// </summary>
    public ConfigurationSetting<string> BuildComponentPath { get; set; }

    /// <summary>
    /// Gets or sets full file name of a list file that contains all files to be
    /// validated.
    /// </summary>
    public ConfigurationSetting<string> BuildListFile { get; set; }

    /// <summary>
    /// Gets or sets the path of the manifest json to use for validation.
    /// </summary>
    [Obsolete("This field is not provided by the user or configFile, set by system")]
    public ConfigurationSetting<string> ManifestPath { get; set; }

    /// <summary>
    /// Gets or sets the root folder where the generated manifest (and other files like bsi.json) files will be placed.
    /// By default we will generate this folder in the same level as the build drop with the name '_manifest'.
    /// </summary>
    public ConfigurationSetting<string> ManifestDirPath { get; set; }

    /// <summary>
    /// Gets or sets the path where the output json should be written.
    /// </summary>
    public ConfigurationSetting<string> OutputPath { get; set; }

    /// <summary>
    /// Gets or sets the number of parallel threads to use for the workflows.
    /// </summary>
    public ConfigurationSetting<int> Parallelism { get; set; }

    /// <summary>
    /// Gets or sets display this amount of detail in the logging output.
    /// </summary>
    public ConfigurationSetting<LogEventLevel> Verbosity { get; set; }

    /// <summary>
    /// Gets or sets the json file that contains the configuration for the DropValidator.
    /// </summary>
    public ConfigurationSetting<string> ConfigFilePath { get; set; }

    /// <summary>
    /// Gets or sets a list of name and version of the manifest that we are generating.
    /// </summary>
    public ConfigurationSetting<IList<ManifestInfo>> ManifestInfo { get; set; }

    /// <summary>
    /// Gets or sets the Hash algorithm to use while verifying the hash value of a file.
    /// </summary>
    public ConfigurationSetting<AlgorithmName> HashAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets if you're downloading only a part of the drop using the '-r' or 'root' parameter
    /// in the drop client, specify the same string value here in order to skip
    /// validating paths that are not downloaded.
    /// </summary>
    public ConfigurationSetting<string> RootPathFilter { get; set; }

    /// <summary>
    /// Gets or sets the path of the signed catalog file used to validate the manifest.json.
    /// </summary>
    public ConfigurationSetting<string> CatalogFilePath { get; set; }

    /// <summary>
    /// Gets or sets if set, will validate the manifest using the signed catalog file.
    /// </summary>
    public ConfigurationSetting<bool> ValidateSignature { get; set; }

    /// <summary>
    /// Gets or sets if set, will not fail validation on the files presented in Manifest but missing on the disk.
    /// </summary>
    public ConfigurationSetting<bool> IgnoreMissing { get; set; }

    /// <summary>
    /// Gets or sets the action currently being performed by the manifest tool.
    /// </summary>
    public ManifestToolActions ManifestToolAction { get; set; }

    /// <summary>
    /// Gets or sets the name of the package this SBOM represents.
    /// </summary>
    public ConfigurationSetting<string> PackageName { get; set; }

    /// <summary>
    /// Gets or sets the version of the package this SBOM represents.
    /// </summary>
    public ConfigurationSetting<string> PackageVersion { get; set; }

    /// <summary>
    /// Gets or sets supplier information of the package this SBOM represents.
    /// </summary>
    public ConfigurationSetting<string> PackageSupplier { get; set; }

    /// <summary>
    /// Gets or sets a list of <see cref="SbomFile"/> files provided to us from the API.
    /// We won't traverse the build root path to get a list of files if this is set, and
    /// use the list provided here instead.
    /// </summary>
    public ConfigurationSetting<IEnumerable<SbomFile>> FilesList { get; set; }

    /// <summary>
    /// Gets or sets a list of <see cref="SbomPackage"/> packages provided to us from the API.
    /// This list will be used to generate the packages in the final SBOM.
    /// </summary>
    public ConfigurationSetting<IEnumerable<SbomPackage>> PackagesList { get; set; }

    /// <summary>
    /// Gets or sets if specified, we will store the generated telemetry for the execution
    /// of the SBOM tool at this path.
    /// </summary>
    public ConfigurationSetting<string> TelemetryFilePath { get; set; }

    /// <summary>
    /// Gets or sets comma separated list of docker image names or hashes to be scanned for packages, ex: ubuntu:16.04, 56bab49eef2ef07505f6a1b0d5bd3a601dfc3c76ad4460f24c91d6fa298369ab.
    /// </summary>
    [ComponentDetectorArgument(nameof(DockerImagesToScan))]
    public ConfigurationSetting<string> DockerImagesToScan { get; set; }

    /// <summary>
    /// Gets or sets full file path to a file that contains list of external SBOMs to be
    /// included as External document reference.
    /// </summary>
    public ConfigurationSetting<string> ExternalDocumentReferenceListFile { get; set; }

    /// <summary>
    /// Gets or sets additional set of command-line arguments for Component Detector.
    /// </summary>
    [ComponentDetectorArgument]
    public ConfigurationSetting<string> AdditionalComponentDetectorArgs { get; set; }

    /// <summary>
    /// Gets or sets unique part of the namespace uri for SPDX 2.2 SBOMs. This value should be globally unique.
    /// If this value is not provided, we generate a unique guid that will make the namespace globally unique.
    /// </summary>
    public ConfigurationSetting<string> NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// Gets or sets the base of the URI that will be used to generate this SBOM. This should be a value that identifies that
    /// the SBOM belongs to a single publisher (or company).
    /// </summary>
    public ConfigurationSetting<string> NamespaceUriBase { get; set; }

    /// <summary>
    /// Gets or sets a timestamp in the format <code>yyyy-MM-ddTHH:mm:ssZ</code> that will be used as the generated timestamp for the SBOM.
    /// </summary>
    public ConfigurationSetting<string> GenerationTimestamp { get; set; }

    /// <summary>
    /// If set to false, we will not follow symlinks while traversing the build drop folder. Default is set to 'true'.
    /// </summary>
    public ConfigurationSetting<bool> FollowSymlinks { get; set; }

    /// <summary>
    /// If set to true, we will delete any previous manifest directories that are already present in the ManifestDirPath without asking the user
    /// for confirmation. The new manifest directory will then be created at this location and the generated SBOM will be stored there.
    /// </summary>
    public ConfigurationSetting<bool> DeleteManifestDirIfPresent { get; set; }

    /// <summary>
    /// If set to true, validation will fail if the SBOM does not contain any packages.
    /// </summary>
    public ConfigurationSetting<bool> FailIfNoPackages { get; set; }

    /// <summary>
    /// If set to true, we will attempt to fetch license information of packages detected in the SBOM from the ClearlyDefinedApi.
    /// </summary>
    public ConfigurationSetting<bool> FetchLicenseInformation { get; set; }

    /// <summary>
    /// If set to true, we will attempt to locate and parse package metadata files for additional information to include in the SBOM such as .nuspec/.pom files in the local package cache.
    /// </summary>
    public ConfigurationSetting<bool> EnablePackageMetadataParsing { get; set; }

    /// <summary>
    /// Gets or sets the file path of the SBOM to redact.
    /// </summary>
    public ConfigurationSetting<string> SbomPath { get; set; }

    /// <summary>
    /// Gets or sets the directory containing the sbom(s) to redact.
    /// </summary>
    public ConfigurationSetting<string> SbomDir { get; set; }

    /// <summary>
    /// The conformance to validate against.
    /// </summary>
    public ConfigurationSetting<ConformanceType> Conformance { get; set; }

    /// Specifies the timeout in seconds for fetching the license information. Defaults to <see cref="Constants.DefaultLicenseFetchTimeoutInSeconds"/>.
    /// Has no effect if FetchLicenseInformation (li) argument is false or not provided. Negative values are set to the default and values exceeding the
    /// maximum are truncated to <see cref="Constants.MaxLicenseFetchTimeoutInSeconds"/>
    /// </summary>
    public ConfigurationSetting<int> LicenseInformationTimeoutInSeconds { get; set; }

    /// <summary>
    /// Describes the artifacts used for aggregation, as well information specific to each artifact.
    /// The Key is the location of the artifact, and the value is an <see cref="ArtifactInfo"/> object.
    /// </summary>
    public ConfigurationSetting<Dictionary<string, ArtifactInfo>> ArtifactInfoMap { get; set; }

    /// <summary>
    /// Describes package dependencies in the form of source-destination pairs.
    /// </summary>
    public ConfigurationSetting<IEnumerable<KeyValuePair<string, string>>> PackageDependenciesList { get; set; }
}
