// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders;
using Microsoft.Sbom.Api.Providers.FilesProviders;
using Microsoft.Sbom.Api.Providers.PackagesProviders;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.Sbom.Contracts.Interfaces;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;

/// <summary>
/// MSBuild task for generating SBOMs from build output.
/// </summary>
public class GenerateSbomTask : Task
{
    /// <summary>
    /// The path to the drop directory for which the SBOM will be generated.
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

    /// <summary>
    /// The path to the generated SBOM directory.
    /// </summary>
    [Output]
    public string SbomPath { get; set; }

    private ISBOMGenerator Generator { get; set; }

    /// <summary>
    /// Constructor for the GenerateSbomTask.
    /// </summary>
    public GenerateSbomTask()
    {
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices((host, services) =>
                services
                .AddSbomTool()
                /* Manually adding some dependencies since `AddSbomTool()` does not add them when
                 * running the MSBuild Task from another project.
                 */
                .AddSingleton<ISourcesProvider, SBOMPackagesProvider>()
                .AddSingleton<ISourcesProvider, CGExternalDocumentReferenceProvider>()
                .AddSingleton<ISourcesProvider, DirectoryTraversingFileToJsonProvider>()
                .AddSingleton<ISourcesProvider, ExternalDocumentReferenceFileProvider>()
                .AddSingleton<ISourcesProvider, ExternalDocumentReferenceProvider>()
                .AddSingleton<ISourcesProvider, FileListBasedFileToJsonProvider>()
                .AddSingleton<ISourcesProvider, SbomFileBasedFileToJsonProvider>()
                .AddSingleton<ISourcesProvider, CGScannedExternalDocumentReferenceFileProvider>()
                .AddSingleton<ISourcesProvider, CGScannedPackagesProvider>()
                .AddSingleton<IAlgorithmNames, AlgorithmNames>()
                .AddSingleton<IManifestGenerator, Generator>()
                .AddSingleton<IMetadataProvider, LocalMetadataProvider>()
                .AddSingleton<IMetadataProvider, SBOMApiMetadataProvider>()
                .AddSingleton<IManifestInterface, Validator>()
                .AddSingleton<IManifestConfigHandler, SPDX22ManifestConfigHandler>())
            .Build();
        this.Generator = host.Services.GetRequiredService<ISBOMGenerator>();
    }

    /// <inheritdoc/>
    public override bool Execute()
    {
        try
        {
            // Validate required args and args that take paths as input.
            if (!ValidateAndSanitizeRequiredParams() || !ValidateAndSanitizeNamespaceUriUniquePart())
            {
                return false;
            }

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
                Verbosity = ValidateAndAssignVerbosity(),
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

            SbomPath = !string.IsNullOrWhiteSpace(result.ManifestDirPath) ? Path.GetFullPath(result.ManifestDirPath) : null;
            return result.IsSuccessful;
        }
        catch (Exception e)
        {
            // TODO: Add automated tests for the different exceptions.
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }

    private string Remove_Spaces_Tabs_Newlines(string value)
    {
        return value.Replace("\n", string.Empty).Replace("\t", string.Empty).Replace(" ", string.Empty);
    }

    /// <summary>
    /// Ensure all required arguments are non-null/empty,
    /// and do not contain whitespaces, tabs, or newline characters.
    /// </summary>
    /// <returns>True if the required parameters are valid. False otherwise.</returns>
    private bool ValidateAndSanitizeRequiredParams()
    {
        if (string.IsNullOrWhiteSpace(this.BuildDropPath))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.BuildDropPath)}. Please provide a valid path.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageSupplier))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageSupplier)}. Please provide a valid supplier name.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageName))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageName)}. Please provide a valid name.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageVersion))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageVersion)}. Please provide a valid version number.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.NamespaceBaseUri))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.NamespaceBaseUri)}. Please provide a valid URI.");
            return false;
        }

        this.PackageSupplier = Remove_Spaces_Tabs_Newlines(this.PackageSupplier);
        this.PackageName = Remove_Spaces_Tabs_Newlines(this.PackageName);
        this.PackageVersion = Remove_Spaces_Tabs_Newlines(this.PackageVersion);
        this.NamespaceBaseUri = this.NamespaceBaseUri.Trim();
        this.BuildDropPath = this.BuildDropPath.Trim();

        return true;
    }

    /// <summary>
    /// Checks the user's input for Verbosity and assigns the
    /// associated EventLevel value for logging.
    /// </summary>
    private EventLevel ValidateAndAssignVerbosity()
    {
        if (string.IsNullOrWhiteSpace(this.Verbosity))
        {
            Log.LogMessage($"No verbosity level specified. Setting verbosity level at \"{EventLevel.LogAlways}\"");
            return EventLevel.LogAlways;
        }

        if (Enum.TryParse(this.Verbosity, true, out EventLevel eventLevel))
        {
            return eventLevel;
        }

        Log.LogMessage($"Unrecognized verbosity level specified. Setting verbosity level at \"{EventLevel.LogAlways}\"");
        return EventLevel.LogAlways;
    }

    /// <summary>
    /// Check for ManifestInfo and create an SbomSpecification accordingly.
    /// </summary>
    /// <returns>A list of the parsed manifest info. Null ig the manifest info is null or empty.</returns>
    private IList<SbomSpecification> ValidateAndAssignSpecifications()
    {
        if (!string.IsNullOrWhiteSpace(this.ManifestInfo))
        {
           return [SbomSpecification.Parse(this.ManifestInfo)];
        }

        return null;
    }

    /// <summary>
    /// Ensure a valid NamespaceUriUniquePart is provided.
    /// </summary>
    /// <returns>True if the Namespace URI unique part is valid. False otherwise.</returns>
    private bool ValidateAndSanitizeNamespaceUriUniquePart()
    {
        // Ensure the NamespaceUriUniquePart is valid if provided.
        if (!string.IsNullOrWhiteSpace(this.NamespaceUriUniquePart)
            && (!Guid.TryParse(this.NamespaceUriUniquePart, out _)
            || this.NamespaceUriUniquePart.Equals(Guid.Empty.ToString())))
        {
            Log.LogError($"SBOM generation failed: NamespaceUriUniquePart '{this.NamespaceUriUniquePart}' must be a valid unique GUID.");
            return false;
        }
        else if (!string.IsNullOrWhiteSpace(this.NamespaceUriUniquePart))
        {
            this.NamespaceUriUniquePart = this.NamespaceUriUniquePart.Trim();
        }

        return true;
    }
}
