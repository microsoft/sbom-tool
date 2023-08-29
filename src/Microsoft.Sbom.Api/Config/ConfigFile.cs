﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Serilog.Events;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// This is the schema for the config file that is used to provide
/// the validator with additional params in a JSON format. Most of 
/// these fields can also be provided through the command line. In case
/// of a conflict (same value provided in config file and command line, we
/// throw an input error.
/// </summary>
public class ConfigFile
{
    /// <summary>
    /// Gets or sets the root folder of the drop directory to validate.
    /// </summary>
    public string BuildDropPath { get; set; }

    /// <summary>
    /// Gets or sets the folder containing the build components and packages.
    /// </summary>
    public string BuildComponentPath { get; set; }

    /// <summary>
    /// Gets or sets the file path containing a list of files for which the manifest file will be generated.
    /// </summary>
    public string BuildListFile { get; set; }

    /// <summary>
    /// Gets or sets the path of the manifest json to use for validation.
    /// </summary>
    [Obsolete("This property is obsolete. Value will by generated by the system.")]
    public string ManifestPath { get; set; }

    /// <summary>
    /// Gets or sets the root folder where the generated manifest (and other files like bsi.json) files will be placed.
    /// By default we will generate this folder in the same level as the build drop with the name '_manifest'.
    /// </summary>
    public string ManifestDirPath { get; set; }

    /// <summary>
    /// Gets or sets the path where the output json should be written.
    /// </summary>
    public string OutputPath { get; set; }

    /// <summary>
    /// Gets or sets the path of the signed catalog file used to validate the manifest.json.
    /// </summary>
    public string CatalogFilePath { get; set; }

    /// <summary>
    /// Gets or sets if set, will validate the manifest using the signed catalog file.
    /// </summary>
    public bool? ValidateSignature { get; set; }

    /// <summary>
    /// Gets or sets if set, will not fail validation on the files presented in Manifest but missing on the disk.
    /// </summary>
    public bool? IgnoreMissing { get; set; }

    /// <summary>
    /// Gets or sets if you're downloading only a part of the drop using the '-r' or 'root' parameter
    /// in the drop client, specify the same string value here in order to skip
    /// validating paths that are not downloaded.
    /// </summary>
    public string RootPathFilter { get; set; }

    /// <summary>
    /// Gets or sets display this amount of detail in the logging output.
    /// </summary>
    public LogEventLevel? Verbosity { get; set; }

    /// <summary>
    /// Gets or sets the number of parallel threads to run for the validator.
    /// </summary>
    public int? Parallelism { get; set; }

    /// <summary>
    /// Gets or sets a list of the name and version of the manifest format that we are using.
    /// </summary>
    public IList<ManifestInfo> ManifestInfo { get; set; }

    /// <summary>
    /// Gets or sets the Hash algorithm to use while verifying or generating the hash value of a file.
    /// </summary>
    public AlgorithmName HashAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the name of the package this SBOM represents.
    /// </summary>
    public string PackageName { get; set; }

    /// <summary>
    /// Gets or sets the version of the package this SBOM represents.
    /// </summary>
    public string PackageVersion { get; set; }

    /// <summary>
    /// Gets or sets the supplier of the package this SBOM represents.
    /// </summary>
    public string PackageSupplier { get; set; }

    /// <summary>
    /// Gets or sets a JSON config file that can be used to specify all the arguments for an action.
    /// </summary>
    [JsonIgnore]
    public string ConfigFilePath { get; set; }

    [JsonIgnore]
    public ManifestToolActions ManifestToolAction { get; set; }

    /// <summary>
    /// Gets or sets if specified, we will store the generated telemetry for the execution
    /// of the SBOM tool at this path.
    /// </summary>        
    public string TelemetryFilePath { get; set; }

    /// <summary>
    /// Gets or sets comma separated list of docker image names or hashes to be scanned for packages, ex: ubuntu:16.04, 56bab49eef2ef07505f6a1b0d5bd3a601dfc3c76ad4460f24c91d6fa298369ab.
    /// </summary>
    public string DockerImagesToScan { get; set; }

    /// <summary>
    /// Gets or sets the file path containing a list of external SBOMs to include as external document reference.
    /// </summary>
    public string ExternalDocumentReferenceListFile { get; set; }

    /// <summary>
    /// Gets or sets additional set of command-line arguments for Component Detector.
    /// </summary>
    public string AdditionalComponentDetectorArgs { get; set; }

    /// <summary>
    /// Gets or sets unique part of the namespace uri for SPDX 2.2 SBOMs. This value should be globally unique.
    /// If this value is not provided, we generate a unique guid that will make the namespace globally unique.
    /// </summary>
    public string NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// Gets or sets the base of the URI that will be used to generate this SBOM. This should be a value that identifies that
    /// the SBOM belongs to a single publisher (or company).
    /// </summary>
    public string NamespaceUriBase { get; set; }

    /// <summary>
    /// Gets or sets a timestamp in the format. <code>yyyy-MM-ddTHH:mm:ssZ</code> that will be used as the generated timestamp for the SBOM.
    /// </summary>
    public string GenerationTimestamp { get; set; }

    /// <summary>
    /// Gets or sets if set to false, we will not follow symlinks while traversing the build drop folder.
    /// </summary>
    public bool? FollowSymlinks { get; set; }

    /// <summary>
    /// If set to true, we will delete any previous manifest directories that are already present in the ManifestDirPath without asking the user
    /// for confirmation. The new manifest directory will then be created at this location and the generated SBOM will be stored there.
    /// </summary>
    public bool? DeleteManifestDirIfPresent { get; set; }

    /// <summary>
    /// If set to true, we will fail the validation if no packages are found in the build drop.
    /// </summary>
    public bool? FailIfNoPackages { get; set; }

    /// <summary>
    /// If set to true, we will attempt to fetch license information of packages detected in the SBOM from the ClearlyDefinedApi.
    /// </summary>
    public bool? FetchLicenseInformation { get; set; }
}