// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Filters
{
    /// <summary>
    /// This filter checks if the path of a file matches the provided 
    /// root path filter, and returns true if it does. 
    /// </summary>
    public class DownloadedRootPathFilter : IFilter<DownloadedRootPathFilter>
    {
        private readonly IConfiguration configuration;
        private readonly IFileSystemUtils fileSystemUtils;
        private readonly ILogger logger;

        private bool skipValidation;
        private HashSet<string> validPaths;

        public DownloadedRootPathFilter(
            IConfiguration configuration,
            IFileSystemUtils fileSystemUtils,
            ILogger logger)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));

            Init();
        }

        /// <summary>
        /// Returns true if filePath is present in root path filters.
        /// 
        /// For example, say filePath is /root/parent1/parent2/child1/child2.txt, then if the root path
        /// filters contains /root/parent1/ or /root/parent1/parent2/ in it, this filePath with return true,
        /// but if the root path contains /root/parent3/, this filePath will return false.
        /// 
        /// </summary>
        /// <param name="filePath">The file path to validate.</param>
        /// <returns></returns>
        public bool IsValid(string filePath)
        {
            if (skipValidation)
            {
                return true;
            }

            if (string.IsNullOrEmpty(filePath))
            {
                return false;
            }

            bool isValid = false;
            var normalizedPath = new FileInfo(filePath).FullName;

            foreach (var validPath in validPaths)
            {
                isValid |= normalizedPath.StartsWith(validPath, StringComparison.InvariantCultureIgnoreCase);
            }

            return isValid;
        }

        /// <summary>
        /// Initializes the root path filters list.
        /// </summary>
        public void Init()
        {
            logger.Verbose("Adding root path filter valid paths");
            skipValidation = true;

            if (configuration.RootPathFilter != null && !string.IsNullOrWhiteSpace(configuration.RootPathFilter.Value))
            {
                skipValidation = false;
                validPaths = new HashSet<string>();
                string[] relativeRootPaths = configuration.RootPathFilter.Value.Split(';');

                validPaths.UnionWith(relativeRootPaths.Select(r =>
                        new FileInfo(fileSystemUtils.JoinPaths(configuration.BuildDropPath.Value, r))
                                .FullName));

                foreach (var validPath in validPaths)
                {
                    logger.Verbose($"Added valid path {validPath}");
                }
            }
        }
    }
}
