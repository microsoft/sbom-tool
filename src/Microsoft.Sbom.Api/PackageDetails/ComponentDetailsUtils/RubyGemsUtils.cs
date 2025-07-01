// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
public class RubyGemsUtils : IPackageManagerUtils<RubyGemsUtils>
{
    private const int ExecutableIndex = 1;
    private string rubyGemsPath;

    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger logger;
    private readonly IRecorder recorder;
    private readonly IProcessExecutor processExecutor;

    public RubyGemsUtils(IFileSystemUtils fileSystemUtils, ILogger logger, IRecorder recorder, IProcessExecutor processExecutor)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.processExecutor = processExecutor ?? throw new ArgumentNullException(nameof(processExecutor));
    }

    // Takes in a scanned component and attempts to find the associated gemspec file. If it is not found then it returns null.
    public string? GetMetadataLocation(ScannedComponent scannedComponent)
    {
        if (string.IsNullOrEmpty(rubyGemsPath))
        {
            rubyGemsPath = GetRubyGemsSpecificationsPath();
        }

        var gemspecLocation = rubyGemsPath;

        if (string.IsNullOrEmpty(gemspecLocation))
        {
            return null;
        }

        var componentName = scannedComponent.Component.PackageUrl?.Name.ToLower();
        var componentVersion = scannedComponent.Component.PackageUrl?.Version;

        var gemspecFileName = $"{componentName}-{componentVersion}.gemspec";

        var fullGemspecPath = Path.Join(gemspecLocation, gemspecFileName);

        fullGemspecPath = Path.GetFullPath(fullGemspecPath);

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
                gemspecLocation = Path.Join(directory, gemspecFileName);

                if (fileSystemUtils.FileExists(gemspecLocation))
                {
                    return Path.GetFullPath(gemspecLocation);
                }
            }

            logger.Verbose("Could not find gemspec file for {GemspecFileName}", gemspecFileName);
        }

        return null;
    }

    public ParsedPackageInformation ParseMetadata(string gemspecLocation)
    {
        var supplierField = string.Empty;
        var licenseField = string.Empty;

        // Regex patterns for finding the relevant properties of the .gemspec file.
        var namePattern = @"(?:s|spec)\.nam(?:e|es)\s*=\s*""([^""]+)""";
        var versionPattern = @"(?:s|spec)\.version\s*=\s*""([^""]+)""";
        var authorsPattern = @"(?:s|spec)\.autho(?:r|rs)\s*=\s*\[([^\]]+)\]";
        var licensesPattern = @"(?:s|spec)\.licens(?:e|es)\s*=\s*\[([^\]]+)\]";

        try
        {
            if (!fileSystemUtils.FileExists(gemspecLocation))
            {
                throw new PackageMetadataParsingException("Gemspec file not found.");
            }

            var fileContent = fileSystemUtils.ReadAllText(gemspecLocation);

            var name = GetMatchesFromPattern(fileContent, namePattern);
            var version = GetMatchesFromPattern(fileContent, versionPattern);

            // Without name and version we cannot map results to a component so we can skip the rest of the logic if name and version aren't successfully found.
            if (name.Count == 1 && version.Count == 1)
            {
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
            else
            {
                recorder.RecordMetadataException(new PackageMetadataParsingException($"Failed to find name/version for the file {gemspecLocation}"));
                return null;
            }
        }
        catch (PackageMetadataParsingException e)
        {
            logger.Error("Error encountered while extracting supplier info from gemspec file. Supplier information may be incomplete.", e);
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
            var processOutput = string.Empty;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
               processOutput = processExecutor.ExecuteCommand("where", "gem", 1000);
            }
            else
            {
               processOutput = processExecutor.ExecuteCommand("which", "gem", 1000);
            }

            if (!string.IsNullOrEmpty(processOutput) && processOutput.Contains("\r\n"))
            {
                processOutput = processOutput.Split("\r\n")[ExecutableIndex]; // This will result in two paths with the first being the gem executable directory and the second being the path to the actual executable.
            }

            return processOutput;
        }
        catch (Exception e)
        {
            logger.Error("Error encountered while finding gem executable path: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }

    /// <summary>
    /// Relies on the FindGemExecutablePath() method to execute 'gem env gempath' to determine the base directory of the .gemspec files.
    /// </summary>
    /// <returns>Path to the base specifications directory which holds the .gemspec files.</returns>
    private string GetRubyGemsSpecificationsPath()
    {
        try
        {
            var gemExecutablePath = FindGemExecutablePath();
            var processOutput = string.Empty;

            if (string.IsNullOrEmpty(gemExecutablePath) || !fileSystemUtils.FileExists(gemExecutablePath))
            {
                logger.Error("Unable to find gem executable.");
                return null;
            }

            processOutput = processExecutor.ExecuteCommand(gemExecutablePath, "env gempath", 10000);
            var potentialGemEnvPaths = new List<string>();

            if (processOutput.Contains(';'))
            {
                potentialGemEnvPaths.AddRange(processOutput.Split(';'));
            }
            else if (processOutput.Contains(':'))
            {
                potentialGemEnvPaths.AddRange(processOutput.Split(':'));
            }

            // check if any of the paths exist and have read permissions
            foreach (var path in potentialGemEnvPaths)
            {
                var trimmedPath = path.TrimEnd('\r', '\n');

                trimmedPath = Path.Join(trimmedPath, "specifications");

                if (fileSystemUtils.DirectoryExists(trimmedPath))
                {
                    return trimmedPath;
                }
            }

            return processOutput;
        }
        catch (Exception e)
        {
            logger.Error("Error encountered while running 'gem env gempath' command: ", e);
            recorder.RecordMetadataException(e);
            return null;
        }
    }
}
