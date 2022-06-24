﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Serilog;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;

namespace Microsoft.Sbom.Common
{
    public class OSUtils : IOSUtils
    {
        private readonly OSPlatform osPlatform;

        private readonly OSPlatform[] oSPlatforms = new OSPlatform[]
        {
            OSPlatform.Windows,
            OSPlatform.OSX,
            OSPlatform.Linux
        };

        private readonly ILogger logger;

        private readonly IEnvironmentWrapper environment;

        private Dictionary<string, string> environmentVariables;

        public OSUtils(ILogger logger, IEnvironmentWrapper environment)
        {
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.environment = environment ?? throw new ArgumentException(nameof(environment));
            environmentVariables = new Dictionary<string, string>();

            foreach (DictionaryEntry de in this.environment.GetEnvironmentVariables())
            {
                environmentVariables.Add(de.Key.ToString(), de.Value.ToString());
            }

            foreach (OSPlatform os in oSPlatforms)
            {
                if (RuntimeInformation.IsOSPlatform(os))
                {
                    osPlatform = os;
                    break;
                }
            }
        }

        public OSPlatform GetCurrentOSPlatform() => osPlatform;

        public string GetEnvironmentVariable(string variableName)
        {
            var variableNameValues = environmentVariables.Where(ev => ev.Key.Equals(variableName, StringComparison.OrdinalIgnoreCase)).Select(ev => ev.Value);

            try
            {
                var firstEnvVarInstance = variableNameValues.SingleOrDefault();
                return firstEnvVarInstance;
            }
            catch (InvalidOperationException)
            {
                var firstEnvVarInstance = variableNameValues.First();
                logger.Warning($"There are duplicate environment variables in different case for {variableName}, the value used is {firstEnvVarInstance}");
                return firstEnvVarInstance;
            }
        }

        public StringComparer GetFileSystemStringComparer()
        {
            return IsCaseSensitiveOS() ? StringComparer.InvariantCulture : StringComparer.InvariantCultureIgnoreCase;
        }

        public StringComparison GetFileSystemStringComparisonType()
        {
            return IsCaseSensitiveOS() ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase;
        }

        private bool IsCaseSensitiveOS()
        {
            var currentOS = GetCurrentOSPlatform();
            var isCaseSensitiveOS = currentOS == OSPlatform.Linux || currentOS == OSPlatform.OSX;

            return isCaseSensitiveOS;
        }
    }
}
