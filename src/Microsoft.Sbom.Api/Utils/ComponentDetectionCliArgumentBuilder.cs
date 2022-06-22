// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Castle.Core.Internal;
using Microsoft.ComponentDetection.Common;
using PowerArgs;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// ComponentDetectionCliArgumentBuilder generates list of CLI params for Component Detection orchestrator.
    /// </summary>
    public class ComponentDetectionCliArgumentBuilder
    {
        private string action;
        private VerbosityMode verbosity = VerbosityMode.Quiet;
        private string sourceDirectory;
        private Dictionary<string, string> detectorArgs = new Dictionary<string, string>();
        private Dictionary<string, string> keyValueArgs = new Dictionary<string, string>();
        private List<string> keyArgs = new List<string>();

        private const string verbosityParamName = "Verbosity";
        private const string sourceDirectoryParamName = "SourceDirectory";
        private const string detectorArgsParamName = "DetectorArgs";

        private const string scanAction = "scan";

        public ComponentDetectionCliArgumentBuilder()
        {
        }

        private void Validate()
        {
            if (action.IsNullOrEmpty())
            {
                throw new ArgumentNullException("Action should be specified.");
            }

            if (sourceDirectory.IsNullOrEmpty())
            {
                throw new ArgumentNullException("Source directory should be specified.");
            }
        }

        public string[] Build()
        {
            Validate();

            var command = $"{action} --{verbosityParamName} {verbosity} --{sourceDirectoryParamName} {sourceDirectory}";

            if (detectorArgs.Any())
            {
                var args = string.Join(",", detectorArgs.Select(arg => $"{arg.Key}={arg.Value}"));
                var detectorArgsCommand = $"--{detectorArgsParamName} {args}";
                command += $" {detectorArgsCommand}";
            }

            if (keyValueArgs.Any())
            {
                var argsList = keyValueArgs
                    .Select(x => new List<string>() { $"--{x.Key}", x.Value.Contains(" ") ? $"\"{x.Value}\"" : x.Value })
                    .SelectMany(x => x)
                    .ToList();
                var argsCommand = string.Join(" ", argsList);
                command += $" {argsCommand}";
            }

            if (keyArgs.Any())
            {
                var keyArgsCommand = string.Join(" ", keyArgs);
                command += $" {keyArgsCommand}";
            }

            return Args.Convert(command.Trim());
        }

        public ComponentDetectionCliArgumentBuilder Scan()
        {
            action = scanAction;
            return this;
        }

        public ComponentDetectionCliArgumentBuilder AddDetectorArg(string name, string value)
        {
            detectorArgs.Add(name, value);
            return this;
        }


        public ComponentDetectionCliArgumentBuilder Verbosity(VerbosityMode verbosity)
        {
            this.verbosity = verbosity;
            return this;
        }

        public ComponentDetectionCliArgumentBuilder SourceDirectory(string directory)
        {
            sourceDirectory = directory;
            return this;
        }

        public ComponentDetectionCliArgumentBuilder AddArg(string name, string value)
        {
            if (name.IsNullOrEmpty())
            {
                throw new ArgumentNullException($"{nameof(name)} should not be null");
            }

            if (value.IsNullOrEmpty())
            {
                throw new ArgumentNullException($"{nameof(value)} should not be null");
            }

            name = name.StartsWith("--") ? name.Substring(2) : name;

            if (name.IsNullOrEmpty())
            {
                throw new ArgumentNullException($"{nameof(name)} should not be null or be empty");
            }

            if (name.Equals(sourceDirectoryParamName, StringComparison.OrdinalIgnoreCase))
            {
                return SourceDirectory(value);
            }

            if (name.Equals(verbosityParamName, StringComparison.OrdinalIgnoreCase))
            {
                if (!Enum.TryParse(value, out VerbosityMode verbosity))
                {
                    throw new ArgumentException($"Invalid verbosity value provided - {value}.");
                }
                return Verbosity(verbosity);
            }

            if (name.Equals(detectorArgsParamName, StringComparison.OrdinalIgnoreCase))
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

            keyValueArgs[name] = value;
            return this;
        }

        public ComponentDetectionCliArgumentBuilder AddArg(string value)
        {
            if (value.IsNullOrEmpty())
            {
                throw new ArgumentNullException($"{nameof(value)} should not be null");
            }

            if (value.StartsWith("--") && !keyArgs.Exists(item => item == value))
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
            if (args.IsNullOrEmpty())
            {
                throw new ArgumentNullException($"{nameof(args)} should not be null");
            }

            var argArray = Args.Convert(args);
            for (int i = 0; i < argArray.Length; i++)
            {
                if (argArray[i].StartsWith("--") && i + 1 < argArray.Length && !argArray[i + 1].StartsWith("--"))
                {
                    AddArg(argArray[i].Substring(2), argArray[i + 1]);
                    i++;
                    continue;
                }
                else if (argArray[i].StartsWith("--"))
                {
                    AddArg(argArray[i].Substring(2));
                }
            }
            return this;
        }
    }
}
