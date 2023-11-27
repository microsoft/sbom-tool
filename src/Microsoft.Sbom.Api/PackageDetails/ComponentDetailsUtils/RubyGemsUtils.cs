// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Serilog;
using File = System.IO.File;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Utilities for retrieving information from rubygems packages that may not be present on the buildDropPath.
/// </summary>
public class RubyGemsUtils : IPackageManagerUtils<RubyGemsUtils>
{
    private const int ExecutableIndex = 1;

    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly IRecorder recorder;

    private readonly string rubyGemsPath;
    private string[] potentialGemEnvPaths;

    public RubyGemsUtils(IFileSystemUtils fileSystemUtils, ILogger log, IRecorder recorder)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));

        this.rubyGemsPath = GetRubyGemsSpecificationsPath();
    }

    // Takes in a scanned component and attempts to find the associated gemspec file. If it is not found then it returns null.
    public string? GetMetadataLocation(ScannedComponent scannedComponent)
    {
        var gemspecLocation = rubyGemsPath;

        if (string.IsNullOrEmpty(gemspecLocation))
        {
            return null;
        }

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        var fullGemspecPath = Path.Join(gemspecLocation, $"{componentName}-{componentVersion}.gemspec");

        if (fileSystemUtils.FileExists(fullGemspecPath))
        {
            return fullGemspecPath;
        }
        else
        {
            // Enumerate directories in the gemspec location and then search for the gemspec file in each directory
            var directories = fileSystemUtils.GetDirectories(gemspecLocation);

            foreach (var directory in directories)
            {
                fullGemspecPath = Path.Join(directory, $"{componentName}-{componentVersion}.gemspec");

                if (fileSystemUtils.FileExists(fullGemspecPath))
                {
                    return Path.GetFullPath(fullGemspecPath);
                }
            }
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
            if (!fileSystemUtils.FileExists(gemspecLocation))
            {
                throw new PackageMetadataParsingException("Gemspec file not found.");
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
            log.Error("Error encountered while extracting supplier info from gemspec file. Supplier information may be incomplete.", e);
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

    /// <summary>
    /// Runs the 'where gem' or "which gem" command based on OS and returns a single path to the gem executable.
    /// </summary>
    /// <returns>A path to the location of the gem executable.</returns>
    private string FindGemExecutablePath()
    {
        try
        {
            var processStartFindGem = null as ProcessStartInfo;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                processStartFindGem = new ProcessStartInfo("where", "gem")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else
            {
                processStartFindGem = new ProcessStartInfo("where", "gem")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }

            using var processFindGem = new Process();
            processFindGem.StartInfo = processStartFindGem;

            processFindGem.Start();
            var gemExecutablePath = processFindGem.StandardOutput.ReadToEnd()?.Trim().ToString();

            processFindGem.WaitForExit();

            if (!string.IsNullOrEmpty(gemExecutablePath) && gemExecutablePath.Contains("\r\n"))
            {
                gemExecutablePath = gemExecutablePath.Split("\r\n")[ExecutableIndex]; // This will result in two paths with the first being the gem executable directory and the second being the path to the actual executable.
            }

            return gemExecutablePath;
        }
        catch (Exception e)
        {
            log.Error("Error encountered while finding gem executable path: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }

    /// <summary>
    /// Relies on the FindGemExecutablePath() method to execute 'gem env gempath' to determine the base directory of the .gemspec files
    /// </summary>
    /// <returns>Path to the base specifications directory which holds the .gemspec files.</returns>
    private string GetRubyGemsSpecificationsPath()
    {
        try
        {
            var gemExecutablePath = FindGemExecutablePath();

            if (string.IsNullOrEmpty(gemExecutablePath) || !File.Exists(gemExecutablePath))
            {
                log.Error("Unable to find gem executable.");
                return null;
            }

            var processStartGemEnvPath = new ProcessStartInfo(gemExecutablePath, "env gempath")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var processGemEnvPath = new Process();
            processGemEnvPath.StartInfo = processStartGemEnvPath;

            processGemEnvPath.Start();
            var output = processGemEnvPath.StandardOutput.ReadToEnd();
            var error = processGemEnvPath.StandardError.ReadToEnd();

            processGemEnvPath.WaitForExit();

            if (output.Contains(';'))
            {
                potentialGemEnvPaths = output.Split(';');
            }
            else if (output.Contains(':'))
            {
                potentialGemEnvPaths = output.Split(':');
            }

            // check if any of the paths exist and have read permissions
            foreach (var path in potentialGemEnvPaths)
            {
                var trimmedPath = path.TrimEnd('\r', '\n');

                trimmedPath = Path.Join(trimmedPath, "specifications");

                if (Directory.Exists(trimmedPath))
                {
                    return trimmedPath;
                }
            }

            return output;
        }
        catch (Exception e)
        {
            log.Error("Error encountered while running 'gem env gempath' command: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }
}
