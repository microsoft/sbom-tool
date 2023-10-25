// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.ComponentDetection.Orchestrator.Commands;
using PowerArgs;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// ComponentDetectionCliArgumentBuilder generates list of CLI params for Component Detection orchestrator.
/// </summary>
public class ComponentDetectionCliArgumentBuilder
{
    private string sourceDirectory;
    private Dictionary<string, string> detectorArgs = new Dictionary<string, string>() {
        { TimeoutArgsParamName, TimeoutDefaultSeconds.ToString() }
    };

    private Dictionary<string, string> keyValueArgs = new Dictionary<string, string>();
    private List<string> keyArgs = new List<string>();

    private const string SourceDirectoryParamName = "SourceDirectory";
    private const string DirectoryExclusionListParamName = "DirectoryExclusionList";
    private const string DetectorArgsParamName = "DetectorArgs";
    private const string TimeoutArgsParamName = "Timeout";
    private const int TimeoutDefaultSeconds = 15 * 60; // 15 minutes

    public ComponentDetectionCliArgumentBuilder()
    {
    }

    private void Validate()
    {
        if (string.IsNullOrEmpty(sourceDirectory))
        {
            throw new ArgumentNullException("Source directory should be specified.");
        }
    }

    public string[] Build()
    {
        Validate();

        var command = $"--{SourceDirectoryParamName} {AsArgumentValue(sourceDirectory)}";

        if (detectorArgs.Any())
        {
            var args = string.Join(",", detectorArgs.Select(arg => $"{arg.Key}={AsArgumentValue(arg.Value)}"));
            var detectorArgsCommand = $"--{DetectorArgsParamName} {args}";
            command += $" {detectorArgsCommand}";
        }

        if (keyValueArgs.Any())
        {
            var argsList = keyValueArgs
                .Select(x => new List<string>() { $"--{x.Key}", AsArgumentValue(x.Value) })
                .SelectMany(x => x)
                .ToList();
            var argsCommand = string.Join(" ", argsList);
            command += $" {argsCommand}";
        }

        if (keyArgs.Any())
        {
            var keyArgsCommand = string.Join(" ", keyArgs.Select(this.AsArgumentValue));
            command += $" {keyArgsCommand}";
        }

        return Args.Convert(command.Trim());
    }

    /// <summary>
    /// Takes a set of parsed arguments for Component Detection and converts them into a ScanSettings object.
    /// </summary>
    /// <param name="args">Set of arguments in the proper format for component detection.</param>
    /// <returns></returns>
    public ScanSettings BuildScanSettingsFromParsedArgs(string[] args)
    {
        Validate();

        // Create a new instance of ScanSettings
        var scanSettings = new ScanSettings();

        for (var i = 0; i < args.Length - 1; i++)
        {
            var argumentName = args[i];
            var argumentValue = args[i + 1];

            // Map the argument to the corresponding property in ScanSettings
            switch (argumentName)
            {
                case "--DirectoryExclusionList":
                    scanSettings.DirectoryExclusionList = argumentValue.Split(';');
                    break;
                case "--SourceDirectory":
                    scanSettings.SourceDirectory = new DirectoryInfo(argumentValue);
                    break;
                case "--SourceFileRoot":
                    scanSettings.SourceFileRoot = new DirectoryInfo(argumentValue);
                    break;
                case "--DetectorArgs":
                    var keyValuePairs = argumentValue.Split(',');
                    foreach (var keyValue in keyValuePairs)
                    {
                        var pair = keyValue.Split('=');
                        if (pair.Length == 2)
                        {
                            scanSettings.DetectorArgs[pair[0]] = pair[1];
                        }
                    }

                    break;
                case "--DetectorCategories":
                    scanSettings.DetectorCategories = argumentValue.Split(",");
                    break;
                case "--ManifestFile":
                    scanSettings.ManifestFile = new FileInfo(argumentValue);
                    break;
                case "--PrintManifest":
                    scanSettings.PrintManifest = bool.Parse(argumentValue);
                    break;
                case "--DockerImagesToScan":
                    scanSettings.DockerImagesToScan = argumentValue.Split(",");
                    break;
            }
        }

        return scanSettings;
    }

    public ComponentDetectionCliArgumentBuilder AddDetectorArg(string name, string value)
    {
        detectorArgs[name] = value;
        return this;
    }

    public ComponentDetectionCliArgumentBuilder SourceDirectory(string directory)
    {
        sourceDirectory = directory;
        return this;
    }

    public ComponentDetectionCliArgumentBuilder AddArg(string name, string value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentNullException($"{nameof(name)} should not be null");
        }

        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentNullException($"{nameof(value)} should not be null");
        }

        name = name.StartsWith("--", StringComparison.Ordinal) ? name.Substring(2) : name;

        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentNullException($"{nameof(name)} should not be null or be empty");
        }

        if (name.Equals(SourceDirectoryParamName, StringComparison.OrdinalIgnoreCase))
        {
            return SourceDirectory(value);
        }

        if (name.Equals(DetectorArgsParamName, StringComparison.OrdinalIgnoreCase))
        {
            var detectorArgs = value.Split(",").Select(arg => arg.Trim()).Select(arg => arg.Split("="));
            if (detectorArgs.Any())
            {
                foreach (var arg in detectorArgs)
                {
                    if (arg.Length >= 2)
                    {
                        AddDetectorArg(arg[0], arg[1]);
                    }
                }
            }

            return this;
        }

        // Check if a value already exists for the the DirectoryExclusionList and if so, append the new value to the existing value
        if (keyValueArgs.ContainsKey(name) && name.Equals(DirectoryExclusionListParamName, StringComparison.OrdinalIgnoreCase))
        {
            keyValueArgs[name] = $"{keyValueArgs[name]};{value}";
            return this;
        }

        keyValueArgs[name] = value;
        return this;
    }

    public ComponentDetectionCliArgumentBuilder AddArg(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentNullException($"{nameof(value)} should not be null");
        }

        if (value.StartsWith("--", StringComparison.Ordinal) && !keyArgs.Exists(item => item == value))
        {
            keyArgs.Add(value);
        }
        else
        {
            var argument = $"--{value}";
            if (!keyArgs.Exists(item => item == argument))
            {
                keyArgs.Add(argument);
            }
        }

        return this;
    }

    public ComponentDetectionCliArgumentBuilder ParseAndAddArgs(string args)
    {
        if (string.IsNullOrEmpty(args))
        {
            throw new ArgumentNullException($"{nameof(args)} should not be null");
        }

        var argArray = Args.Convert(args);
        for (var i = 0; i < argArray.Length; i++)
        {
            if (argArray[i].StartsWith("--", StringComparison.Ordinal) && i + 1 < argArray.Length && !argArray[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                AddArg(argArray[i].Substring(2), argArray[i + 1]);
                i++;
                continue;
            }
            else if (argArray[i].StartsWith("--", StringComparison.Ordinal))
            {
                AddArg(argArray[i].Substring(2));
            }
        }

        return this;
    }

    private string AsArgumentValue(string arg)
    {
        if (arg.Contains(' '))
        {
            return $"\"{arg}\"";
        }

        return arg;
    }
}
