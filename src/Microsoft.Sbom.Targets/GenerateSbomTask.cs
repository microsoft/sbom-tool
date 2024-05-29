// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Threading;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Tool;
using Microsoft.VisualBasic;
using PowerArgs;
using Serilog.Events;

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
    /// The path to the directory containing build components and package information.
    /// For example, path to a .csproj or packages.config file.
    /// </summary>
    public string BuildComponentPath { get; set; }

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
    public bool DeleteManifestDirIfPresent { get; set; } = true;

    /// <summary>
    /// The path where the SBOM will be generated.
    /// </summary>
    public string ManifestDirPath { get; set; }

    [Output]
    public string SbomPath { get; set; }

    private ISBOMGenerator Generator { get; set; }

    public GenerateSbomTask()
    {
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices((host, services) =>
                services
                .AddSbomTool())
            .Build();
        this.Generator = host.Services.GetRequiredService<ISBOMGenerator>();
    }

    public override bool Execute()
    {
        try
        {
            // Set other configurations. The GenerateSBOMAsync() already sanitizes and checks for
            // a valid namespace URI and generates a random guid for NamespaceUriUniquePart if
            // one is not provided.
            var sbomMetadata = new SBOMMetadata
            {
                PackageSupplier = this.PackageSupplier,
                PackageName = this.PackageName,
                PackageVersion = this.PackageVersion,
            };
            var runtimeConfiguration = new RuntimeConfiguration
            {
                NamespaceUriBase = this.NamespaceBaseUri,
                NamespaceUriUniquePart = this.NamespaceUriUniquePart,
                DeleteManifestDirectoryIfPresent = this.DeleteManifestDirIfPresent,
                Verbosity = ValidateAndAssignVerbosity()
            };
#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
            var result = System.Threading.Tasks.Task.Run(() => this.Generator.GenerateSbomAsync(
                rootPath: this.BuildDropPath,
                manifestDirPath: this.ManifestDirPath,
                metadata: sbomMetadata,
                componentPath: this.BuildComponentPath,
                runtimeConfiguration: runtimeConfiguration,
                specifications: ValidateAndAssignSpecifications(),
                externalDocumentReferenceListFile: this.ExternalDocumentListFile)).GetAwaiter().GetResult();
#pragma warning restore VSTHRD002 // Avoid problematic synchronous waits

            SbomPath = "path/to/sbom";
            return result.IsSuccessful;
        }
        catch (Exception e)
        {
            // TODO: Add automated tests for the different exceptions.
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Checks the user's input for Verbosity and assigns the
    /// associated EventLevel value for logging.
    /// </summary>
    private EventLevel ValidateAndAssignVerbosity()
    {
        if (string.IsNullOrEmpty(this.Verbosity))
        {
            Log.LogMessage($"No verbosity level specified. Setting verbosity level at \"{EventLevel.LogAlways}\"");
            return EventLevel.LogAlways;
        }

        if (Enum.TryParse(this.Verbosity, true, out EventLevel eventLevel)) {
            return eventLevel;
        }

        Log.LogMessage($"Unrecognized verbosity level specified. Setting verbosity level at \"{EventLevel.LogAlways}\"");
        return EventLevel.LogAlways;
    }

    /// <summary>
    /// Check for ManifestInfo and create an SbomSpecification accordingly
    /// </summary>
    /// <returns></returns>
    private IList<SbomSpecification> ValidateAndAssignSpecifications()
    {
        if (!string.IsNullOrWhiteSpace(this.ManifestInfo))
        {
           return new List<SbomSpecification> { SbomSpecification.Parse(this.ManifestInfo) };
        }

        return null;
    }
}
