// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Utilities for retrieving information from maven packages that may not be present on the buildDropPath.
/// </summary>
public class MavenUtils : IMavenUtils
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly IRecorder recorder;

    private static readonly string EnvHomePath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "HOMEPATH" : "HOME";
    private static readonly string HomePath = Environment.GetEnvironmentVariable(EnvHomePath);
    private static readonly string MavenPackagesPath = $"{HomePath}/.m2/repository";

    private bool MavenPackagesPathHasReadPermissions => fileSystemUtils.DirectoryHasReadPermissions(MavenPackagesPath);

    private readonly string userDefinedLocalRepositoryPath;

    public MavenUtils(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));

        userDefinedLocalRepositoryPath = GetLocalRepositoryPath();
    }

    // Takes in a scanned component and attempts to find the associated pom file. If it is not found then it returns null.
    public string GetPomLocation(ScannedComponent scannedComponent)
    {
        var pomLocation = MavenPackagesPath;

        // Check if a user-defined local repository exists. If not, continue with the default value.
        if (!string.IsNullOrEmpty(userDefinedLocalRepositoryPath))
        {
            pomLocation = userDefinedLocalRepositoryPath;
        }

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentNamespace = scannedComponent.Component.PackageUrl?.Namespace?.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        // Take the component namespace and split it by "." in order to get the correct path to the .pom
        if (!string.IsNullOrEmpty(componentNamespace))
        {
            var componentNamespaceParts = componentNamespace.Split('.'); // Example: "org.apache.commons.commons-lang3"

            for (var i = 0; i < componentNamespaceParts.Length; i++)
            {
                pomLocation += $"/{componentNamespaceParts[i]}";
            }
        }

        pomLocation += $"/{componentName}/{componentVersion}/{componentName}-{componentVersion}.pom";

        // Check for file permissions on the .m2 directory before attempting to check if the file exists
        if (MavenPackagesPathHasReadPermissions)
        {
            if (fileSystemUtils.FileExists(pomLocation))
            {
                return pomLocation;
            }
            else
            {
                log.Debug($"Pom location could not be found at: {pomLocation}");
            }
        }

        return null;
    }

    public (string Name, string Version, PackageDetails packageDetails) ParsePom(string pomLocation)
    {
        var supplierField = string.Empty;
        var licenseField = string.Empty;

        try
        {
            var pomBytes = fileSystemUtils.ReadAllBytes(pomLocation);
            using var pomStream = new MemoryStream(pomBytes, false);

            var doc = new XmlDocument();
            doc.Load(pomStream);

            XmlNode developersNode = doc["project"]?["developers"];
            XmlNode licensesNode = doc["project"]?["licenses"];
            XmlNode organizationNode = doc["project"]?["organization"];

            var name = doc["project"]?["artifactId"]?.InnerText;
            var version = doc["project"]?["version"]?.InnerText;

            if (organizationNode != null)
            {
                var organizationName = organizationNode["name"]?.InnerText;
                if (!string.IsNullOrEmpty(organizationName))
                {
                    supplierField = $"Organization: {organizationName}";
                }
            }
            else if (developersNode != null)
            {
                // Take the first developer name and use it as the supplier when there is no organization listed.
                var developerName = developersNode["developer"]?["name"]?.InnerText;
                if (!string.IsNullOrEmpty(developerName))
                {
                    supplierField = $"Person: {developerName}";
                }
            }

            if (licensesNode != null)
            {
                foreach (XmlNode licenseNode in licensesNode.ChildNodes)
                {
                    var licenseName = licenseNode["name"]?.InnerText;

                    if (!string.IsNullOrEmpty(licenseName))
                    {
                        licenseField = licenseName;
                    }
                }
            }

            return (name, version, new PackageDetails(licenseField, supplierField));
        }
        catch (Exception e)
        {
            log.Error("Error encountered while extracting supplier info from pom file. Supplier information may be incomplete.", e);
            recorder.RecordMetadataException(e);

            return (null, null, null);
        }
    }

    /// <summary>
    /// Gets the local repository path for the Maven protocol. Returns null if a settings.xml is not found.
    /// </summary>
    /// <returns>The path to the local repository path defined in the settings.xml</returns>
    private static string GetLocalRepositoryPath()
    {
        var m2Path = $"{HomePath}/.m2";

        var userSettingsXmlPath = $"{m2Path}/settings.xml";
        var backupSettingsXmlPath = $"{m2Path}/_settings.xml";

        if (File.Exists(userSettingsXmlPath))
        {
            return GetRepositoryPathFromXml(userSettingsXmlPath);
        }
        else if (File.Exists(backupSettingsXmlPath))
        {
            return GetRepositoryPathFromXml(backupSettingsXmlPath);
        }

        return null;
    }

    private static string GetRepositoryPathFromXml(string settingsXmlFilePath)
    {
        var settingsXmlBytes = File.ReadAllBytes(settingsXmlFilePath);
        using var xmlStream = new MemoryStream(settingsXmlBytes, false);

        var doc = new XmlDocument();
        doc.Load(xmlStream);

        var localRepositoryNode = doc["settings"]?["localRepository"];

        if (localRepositoryNode != null)
        {
            return localRepositoryNode.InnerText;
        }

        return null;
    }
}
