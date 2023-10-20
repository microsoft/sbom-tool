// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using NuGet.Configuration;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

public class PackageDetailsFactory : IPackageDetailsFactory
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly IRecorder recorder;

    public PackageDetailsFactory(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    public ConcurrentDictionary<(string, string), PackageDetailsObject> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents)
    {
        var packageDetailsLocations = GetPackageDetailsLocations(scannedComponents);

        return ExtractPackageDetailsFromFiles(packageDetailsLocations);
    }

    private List<string> GetPackageDetailsLocations(IEnumerable<ScannedComponent> scannedComponents)
    {
        var packageDetailsConfirmedLocations = new List<string>();

        foreach (var scannedComponent in scannedComponents)
        {
            var componentType = scannedComponent.Component.PackageUrl?.Type.ToLower();

            if (componentType == "nuget")
            {
                packageDetailsConfirmedLocations.Add(GetNuspecLocation(scannedComponent));
            }

            if (componentType == "maven")
            {
                packageDetailsConfirmedLocations.Add(GetPomLocation(scannedComponent));
            }
        }

        return packageDetailsConfirmedLocations;
    }

    private ConcurrentDictionary<(string, string), PackageDetailsObject> ExtractPackageDetailsFromFiles(List<string> packageDetailsPaths)
    {
        // Create a var called packageDetailsDictionary where the key is a tuple of the package name and version and the value is a PackageDetailsObject
        var packageDetailsDictionary = new ConcurrentDictionary<(string, string), PackageDetailsObject>();

        foreach (var path in packageDetailsPaths)
        {
            // If path ends in .nuspec then it is a nuspec file
            if (!string.IsNullOrEmpty(path) && path.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
            {
                var nuspecDetails = ParseNuspec(path);
                packageDetailsDictionary.TryAdd((nuspecDetails.Item1, nuspecDetails.Item2), nuspecDetails.Item3);
            }

            if (!string.IsNullOrEmpty(path) && path.EndsWith(".pom", StringComparison.OrdinalIgnoreCase))
            {
                var pomDetails = ParsePom(path);
                packageDetailsDictionary.TryAdd((pomDetails.Item1, pomDetails.Item2), pomDetails.Item3);
            }
        }

        return packageDetailsDictionary;
    }

    // Takes in a scanned component and attempts to find the associated pom file. If it is not found then it returns null.
    private string GetPomLocation(ScannedComponent scannedComponent)
    {
        var envHome = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "HOMEPATH" : "HOME";
        var home = Environment.GetEnvironmentVariable(envHome);

        var mavenPackagesPath = $"{home}/.m2/repository";
        var pomLocation = mavenPackagesPath;

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentNamespace = scannedComponent.Component.PackageUrl?.Namespace?.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        // Take the component namespace and split it by "." in order to get the correct path to the .pom
        var componentNamespaceParts = componentNamespace.Split('.'); // Example: "org.apache.commons.commons-lang3"

        for (var i = 0; i < componentNamespaceParts.Length; i++)
        {
            if (i == 0)
            {
                pomLocation += $"/{componentNamespaceParts[i]}";
            }
            else
            {
                pomLocation += $"/{componentNamespaceParts[i]}";
            }
        }

        pomLocation += $"/{componentName}/{componentVersion}/{componentName}-{componentVersion}.pom";

        // Check for file permissions on the .m2 directory before attempting to check if the file exists
        if (fileSystemUtils.DirectoryHasReadPermissions(mavenPackagesPath))
        {
            if (fileSystemUtils.FileExists(pomLocation))
            {
                return pomLocation;
            }
        }

        return null;
    }

    // Takes in a scanned component and attempts to find the associated nuspec file. If it is not found then it returns null.
    private string GetNuspecLocation(ScannedComponent scannedComponent)
    {
        var nuspecLocation = string.Empty;
        var nugetPackagesPath = SettingsUtility.GetGlobalPackagesFolder(new NullSettings());

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;
        var componentType = scannedComponent.Component.PackageUrl?.Type.ToLower();

        if (componentType == "nuget")
        {
            nuspecLocation = $"{nugetPackagesPath}/{componentName}/{componentVersion}/{componentName}.nuspec";
        }

        // Check for file permissions on the .nuget directory before attempting to check if every file exists
        if (fileSystemUtils.DirectoryHasReadPermissions(nugetPackagesPath))
        {
            if (fileSystemUtils.FileExists(nuspecLocation))
            {
                return nuspecLocation;
            }
        }

        return null;
    }

    // Get the developers section of the pom file
    private (string, string, PackageDetailsObject) ParsePom(string pomLocation)
    {
        var pomInfo = new PackageDetailsObject();

        try
        {
            var pomBytes = File.ReadAllBytes(pomLocation);
            using var pomStream = new MemoryStream(pomBytes, false);

            var doc = new XmlDocument();
            doc.Load(pomStream);

            XmlNode developersNode = doc["project"]?["developers"];
            XmlNode licensesNode = doc["project"]?["licenses"];

            var name = doc["project"]?["artifactId"]?.InnerText;
            var version = doc["project"]?["version"]?.InnerText;

            if (developersNode != null)
            {
                foreach (XmlNode developerNode in developersNode.ChildNodes)
                {
                    var developerName = developerNode["name"]?.InnerText;
                    var developerEmail = developerNode["email"]?.InnerText;

                    if (!string.IsNullOrEmpty(developerName))
                    {
                        pomInfo.Supplier += $"{developerName}";
                    }

                    if (!string.IsNullOrEmpty(developerEmail))
                    {
                        pomInfo.Supplier += $" ({developerEmail}) ";
                    }
                }
            }

            if (licensesNode != null)
            {
                foreach (XmlNode licenseNode in licensesNode.ChildNodes)
                {
                    var licenseName = licenseNode["name"]?.InnerText;

                    if (!string.IsNullOrEmpty(licenseName))
                    {
                        pomInfo.License = licenseName;
                    }
                }
            }

            return (name, version, pomInfo);
        }
        catch (Exception e)
        {
            log.Error("Error encountered while extracting supplier info from pom file. Supplier information may be incomplete.", e);

            // TODO: Add Exceptions to identify when the PackageDetailsFactory is failing.
            recorder.RecordAPIException(e);
            return (null, null, null);
        }
    }

    // Private method that returns an object that is composed of a Tuple of the package name and version and a PackageDetailsObject
    private (string, string, PackageDetailsObject) ParseNuspec(string nuspecPath)
    {
        var nuspecInfo = new PackageDetailsObject();

        try
        {
            var nuspecBytes = File.ReadAllBytes(nuspecPath);
            using var nuspecStream = new MemoryStream(nuspecBytes, false);

            var doc = new XmlDocument();
            doc.Load(nuspecStream);

            XmlNode packageNode = doc["package"];
            XmlNode metadataNode = packageNode["metadata"];

            var name = metadataNode["id"]?.InnerText;
            var version = metadataNode["version"]?.InnerText;
            var authors = metadataNode["authors"]?.InnerText;
            var license = metadataNode["license"];

            if (license != null && license.Attributes["type"].Value != "file")
            {
                nuspecInfo.License = license.InnerText;
            }

            nuspecInfo.Supplier = authors;

            return (name, version, nuspecInfo);
        }
        catch (Exception e)
        {
            log.Error("Error encountered while extracting supplier info from nuspec file. Supplier information may be incomplete.", e);

            // TODO: Add Exceptions to identify when the PackageDetailsFactory is failing.
            recorder.RecordAPIException(e);
            return (null, null, null);
        }
    }
}
