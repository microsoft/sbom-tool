// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
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

    private readonly string sitePackagesPath;

    public PypiUtils(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));

        this.sitePackagesPath = GetPythonSitePackagesPath();
    }

    // Takes in a scanned component and attempts to find the associated gemspec file. If it is not found then it returns null.
    public string? GetMetadataLocation(ScannedComponent scannedComponent)
    {
        var pythonDistInfo = sitePackagesPath;

        if (string.IsNullOrEmpty(pythonDistInfo))
        {
            return null;
        }

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        var fullMetadataPath = Path.Join(pythonDistInfo, $"{componentName}-{componentVersion}.dist-info/metadata");

        if (fileSystemUtils.DirectoryExists(fullMetadataPath))
        {
            return fullMetadataPath;
        }

        return null;
    }

    public ParsedPackageInformation ParseMetadata(string gemspecLocation)
    {
        var supplierField = string.Empty;
        var licenseField = string.Empty;

        // Regex patterns for finding the relevant properties of the .gemspec file.
        var namePattern = @"s.name\s*=\s*""([^""]+)""";
        var versionPattern = @"s.version\s*=\s*""([^""]+)""";
        var authorsPattern = @"s.authors\s*=\s*\[([^\]]+)\]";
        var licensesPattern = @"s\.licens(?:e|es)\s*=\s*\[([^\]]+)\]";

        try
        {
            if (!fileSystemUtils.FileExists(gemspecLocation) || string.IsNullOrEmpty(gemspecLocation))
            {
                throw new PackageMetadataParsingException("METADATA file not found.");
            }

            var fileContent = fileSystemUtils.ReadAllText(gemspecLocation);

            var name = GetMatchesFromPattern(fileContent, namePattern);
            var version = GetMatchesFromPattern(fileContent, versionPattern);

            // We only take the first author to maintain consistency with what we do with the other component types.
            var supplierList = GetMatchesFromPattern(fileContent, authorsPattern);

            if (supplierList.Any())
            {
                supplierField = supplierList.First().Replace("\".freeze", string.Empty);
                supplierField = Regex.Unescape(supplierField);
            }
            else
            {
                supplierField = null;
            }

            var licenseList = GetMatchesFromPattern(fileContent, licensesPattern);

            if (licenseList.Any())
            {
                // Create a list to store processed license entries
                var processedLicenses = new List<string>();

                // Modify each license entry and add it to the list
                foreach (var license in licenseList)
                {
                    var licenseEntry = license.Replace("\".freeze", string.Empty);
                    processedLicenses.Add(licenseEntry);
                }

                licenseField = string.Join(", ", processedLicenses);
            }
            else
            {
                licenseField = null;
            }

            return new ParsedPackageInformation(name.First(), version.First(), new PackageDetails(licenseField, supplierField));
        }
        catch (PackageMetadataParsingException e)
        {
            log.Error("Error encountered while extracting supplier info from METADATA file. Supplier information may be incomplete.", e);
            recorder.RecordMetadataException(e);

            return null;
        }
    }

    /// <summary>
    /// Given a string and a regex pattern this method will return a List of strings containing all matches found.
    /// </summary>
    /// <param name="content">string of text to be pattern matched.</param>
    /// <param name="pattern">regex expression to use on the content.</param>
    /// <returns>A list of strings containing all matches found. If none are found an empty list will be returned.</returns>
    private List<string> GetMatchesFromPattern(string content, string pattern)
    {
        var matches = new List<string>();
        var match = Regex.Match(content, pattern);
        if (match.Success)
        {
            var matchValue = match.Groups[1].Value;
            var matchesArray = matchValue.Split(','); // Splitting multiple authors/licenses
            foreach (var item in matchesArray)
            {
                var value = item.Trim().Trim('"'); // Remove extra spaces and quotes
                matches.Add(value);
            }
        }

        return matches;
    }

    private string ParsePipLocationOutput(string pipLocationCommandOutput)
    {
        return null;
    }

    private string GetPythonSitePackagesPath()
    {
        try
        {
            var processStartShowPipLocation = new ProcessStartInfo("python", "-m pip show pip location")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var processShowPipLocation = new Process();
            processShowPipLocation.StartInfo = processStartShowPipLocation;

            processShowPipLocation.Start();
            var output = processShowPipLocation.StandardOutput.ReadToEnd();
            var error = processShowPipLocation.StandardError.ReadToEnd();

            processShowPipLocation.WaitForExit();

            log.Warning($"Output of python process: {output}");

            return ParsePipLocationOutput(output);
        }
        catch (Exception e)
        {
            log.Error("Error encountered while running 'python -m pip show pip location' command: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }
}
