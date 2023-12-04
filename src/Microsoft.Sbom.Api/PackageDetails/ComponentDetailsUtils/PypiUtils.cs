// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using AutoMapper.Mappers;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Utilities for retrieving information from rubygems packages that may not be present on the buildDropPath.
/// </summary>
public class PypiUtils : IPackageManagerUtils<PypiUtils>
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly IRecorder recorder;
    private readonly IProcessExecutor processExecutor;

    private string sitePackagesPath;

    public PypiUtils(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder, IProcessExecutor processExecutor)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.processExecutor = processExecutor ?? throw new ArgumentNullException(nameof(processExecutor));
    }

    // Takes in a scanned component and attempts to find the associated gemspec file. If it is not found then it returns null.
    public string? GetMetadataLocation(ScannedComponent scannedComponent)
    {
        if (string.IsNullOrEmpty(sitePackagesPath))
        {
            sitePackagesPath = GetPythonSitePackagesPath();
        }

        var pythonDistInfo = sitePackagesPath;

        if (string.IsNullOrEmpty(pythonDistInfo))
        {
            return null;
        }

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        if (componentName.Contains('-'))
        {
            componentName = componentName.Replace('-', '_');
        }

        var fullMetadataPath = Path.Join(pythonDistInfo, $"{componentName}-{componentVersion}.dist-info/metadata");

        if (fileSystemUtils.FileExists(fullMetadataPath))
        {
            return fullMetadataPath;
        }

        log.Error($"Could not find metadata for {componentName}-{componentVersion} at: {fullMetadataPath}");

        return null;
    }

    public ParsedPackageInformation ParseMetadata(string metadataLocation)
    {
        var name = string.Empty;
        var version = string.Empty;
        var supplierField = string.Empty;
        var licenseField = string.Empty;

        try
        {
            if (!fileSystemUtils.FileExists(metadataLocation) || string.IsNullOrEmpty(metadataLocation))
            {
                throw new PackageMetadataParsingException("METADATA file not found.");
            }

            var fileContent = fileSystemUtils.ReadAllText(metadataLocation);

            var fileContentLines = fileContent.Split("\n");

            foreach (var line in fileContentLines)
            {
                var colonIndex = line.IndexOf(':');
                if (colonIndex != -1)
                {
                    var prefix = line.Substring(0, colonIndex).Trim(); // Extract the prefix before the colon

                    switch (prefix.ToLowerInvariant())
                    {
                        case "name":
                            name = line.Substring(colonIndex + 1).Trim();
                            break;
                        case "version":
                            version = line.Substring(colonIndex + 1).Trim();
                            break;
                        case "author" or "maintainer":
                            supplierField = line.Substring(colonIndex + 1).Trim();
                            break;
/*                        case "author-email":
                            supplierField = line.Substring(colonIndex + 1).Trim();
                            break;*/
                        case "license":
                            licenseField = line.Substring(colonIndex + 1).Trim();
                            break;
                        case "license-expression":
                            licenseField = line.Substring(colonIndex + 1).Trim();
                            break;
                        default:
                            break;
                    }
                }
            }

            if (string.IsNullOrEmpty(licenseField))
            {
                log.Error($"Failed to find any LICENSE information for the package {name}-{version}");
            }
            else if (string.IsNullOrEmpty(supplierField))
            {
                log.Error($"Failed to find any SUPPLIER information for the package {name}-{version}");
            }

            return new ParsedPackageInformation(name, version, new PackageDetails(licenseField, supplierField));
        }
        catch (PackageMetadataParsingException e)
        {
            log.Error("Error encountered while extracting supplier info from METADATA file. Supplier information may be incomplete.", e);
            recorder.RecordMetadataException(e);

            return null;
        }
    }

    private string ParsePipLocationOutput(string pipLocationCommandOutput)
    {
        // Split the output by newlines
        var outputLines = pipLocationCommandOutput.Split(Environment.NewLine);

        // look for the line that starts with "Location: "
        var locationLine = outputLines.FirstOrDefault(line => line.StartsWith("Location: ", StringComparison.OrdinalIgnoreCase));

        if (locationLine == null)
        {
            log.Error("Could not find the line that starts with 'Location: ' in the output of 'python -m pip show pip location' command.");
            return null;
        }

        // remove the "Location: " prefix
        locationLine = locationLine.Substring("Location: ".Length);

        // return the location
        return locationLine;
    }

    private string GetPythonSitePackagesPath()
    {
        try
        {
            var processOutput = string.Empty;

            processOutput = processExecutor.ExecuteCommand("python", "-m pip show pip location", 5000);

            return ParsePipLocationOutput(processOutput);
        }
        catch (Exception e)
        {
            log.Error("Error encountered while running 'python -m pip show pip location' command: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }
}
