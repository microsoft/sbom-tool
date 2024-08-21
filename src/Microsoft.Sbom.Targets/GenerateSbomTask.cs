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
public partial class GenerateSbom : Task
{
    private ISBOMGenerator Generator { get; set; }

    /// <summary>
    /// Constructor for the GenerateSbomTask.
    /// </summary>
    public GenerateSbom()
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

            return result.IsSuccessful;
        }
        catch (Exception e)
        {
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Check for ManifestInfo and create an SbomSpecification accordingly.
    /// </summary>
    /// <returns>A list of the parsed manifest info. Null if the manifest info is null or empty.</returns>
    private IList<SbomSpecification> ValidateAndAssignSpecifications()
    {
        if (!string.IsNullOrWhiteSpace(this.ManifestInfo))
        {
           return [SbomSpecification.Parse(this.ManifestInfo)];
        }

        return null;
    }
}
