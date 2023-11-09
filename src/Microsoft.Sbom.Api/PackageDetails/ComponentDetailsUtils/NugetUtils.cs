// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Xml;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using NuGet.Configuration;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Utilities for retrieving information from maven packages that may not be present on the buildDropPath
/// </summary>
public class NugetUtils : INugetUtils
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly IRecorder recorder;

    private static readonly string NugetPackagesPath = SettingsUtility.GetGlobalPackagesFolder(new NullSettings());

    public NugetUtils(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    // Takes in a scanned component and attempts to find the associated nuspec file. If it is not found then it returns null.
    public string GetNuspecLocation(ScannedComponent scannedComponent)
    {
        var nuspecLocation = string.Empty;

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;
        var componentType = scannedComponent.Component.PackageUrl?.Type.ToLower();

        if (componentType == "nuget")
        {
            nuspecLocation = $"{NugetPackagesPath}/{componentName}/{componentVersion}/{componentName}.nuspec";
        }

        // Check for file permissions on the .nuget directory before attempting to check if every file exists
        if (fileSystemUtils.DirectoryHasReadPermissions(NugetPackagesPath))
        {
            if (fileSystemUtils.FileExists(nuspecLocation))
            {
                return nuspecLocation;
            }
            else
            {
                log.Debug($"Nuspec file could not be found at: {nuspecLocation}");
            }
        }

        return null;
    }

    public (string Name, string Version, PackageDetails packageDetails) ParseNuspec(string nuspecPath)
    {
        var supplierField = string.Empty;
        var licenseField = string.Empty;

        try
        {
            var nuspecBytes = fileSystemUtils.ReadAllBytes(nuspecPath);
            using var nuspecStream = new MemoryStream(nuspecBytes, false);

            var doc = new XmlDocument();
            doc.Load(nuspecStream);

            XmlNode packageNode = doc["package"];
            XmlNode metadataNode = packageNode["metadata"];

            var name = metadataNode["id"]?.InnerText;
            var version = metadataNode["version"]?.InnerText;
            var authors = metadataNode["authors"]?.InnerText;
            var license = metadataNode["license"];

            if (license != null && license.Attributes?["type"].Value != "file")
            {
                licenseField = license.InnerText;
            }

            if (!string.IsNullOrEmpty(authors))
            {
                // If authors contains a comma, then split it and put it back together with a comma and space.
                if (authors.Contains(','))
                {
                    var authorsArray = authors.Split(',');
                    supplierField = string.Join(", ", authorsArray);
                }
                else
                {
                    supplierField = authors;
                }
            }

            return (name, version, new PackageDetails(licenseField, supplierField));
        }
        catch (Exception e)
        {
            log.Error("Error encountered while extracting supplier info from nuspec file. Supplier information may be incomplete.", e);
            recorder.RecordMetadataException(e);

            return (null, null, null);
        }
    }
}
