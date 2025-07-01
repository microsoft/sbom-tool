// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Serilog;

namespace Microsoft.Sbom.Api.Filters;

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
    private List<string> patterns;

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
    /// Returns true if filePath is present in root path filters or matches root path patterns.
    ///
    /// For example, say filePath is /root/parent1/parent2/child1/child2.txt, then if the root path
    /// filters contains /root/parent1/ or /root/parent1/parent2/ in it, this filePath with return true,
    /// but if the root path contains /root/parent3/, this filePath will return false.
    ///
    /// If patterns are specified, the filePath will be matched against glob-style patterns instead.
    /// </summary>
    /// <param name="filePath">The file path to validate.</param>
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

        // If patterns are configured, use pattern matching
        if (patterns != null && patterns.Count > 0)
        {
            return IsValidWithPatterns(filePath);
        }

        // Fall back to legacy path prefix matching
        return IsValidWithPathPrefix(filePath);
    }

    /// <summary>
    /// Validates file path using glob-style patterns.
    /// </summary>
    /// <param name="filePath">The file path to validate.</param>
    /// <returns>True if the path matches any pattern, false otherwise.</returns>
    private bool IsValidWithPatterns(string filePath)
    {
        var buildDropPath = configuration.BuildDropPath?.Value;

        foreach (var pattern in patterns)
        {
            if (PathPatternMatcher.IsMatch(filePath, pattern, buildDropPath))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Validates file path using the legacy path prefix approach.
    /// </summary>
    /// <param name="filePath">The file path to validate.</param>
    /// <returns>True if the path starts with any valid path prefix, false otherwise.</returns>
    private bool IsValidWithPathPrefix(string filePath)
    {
        if (validPaths == null || validPaths.Count == 0)
        {
            return false;
        }

        var isValid = false;
        var normalizedPath = new FileInfo(filePath).FullName;

        foreach (var validPath in validPaths)
        {
            isValid |= normalizedPath.StartsWith(validPath, StringComparison.InvariantCultureIgnoreCase);
        }

        return isValid;
    }

    /// <summary>
    /// Initializes the root path filters list or patterns.
    /// </summary>
    public void Init()
    {
        logger.Verbose("Adding root path filter valid paths");
        skipValidation = true;

        // Check for new pattern-based configuration first (takes precedence)
        if (configuration.RootPathPatterns != null && !string.IsNullOrWhiteSpace(configuration.RootPathPatterns.Value))
        {
            skipValidation = false;
            patterns = new List<string>();
            var patternStrings = configuration.RootPathPatterns.Value.Split(';');

            foreach (var pattern in patternStrings)
            {
                var trimmedPattern = pattern.Trim();
                if (!string.IsNullOrEmpty(trimmedPattern))
                {
                    patterns.Add(trimmedPattern);
                    logger.Verbose($"Added pattern {trimmedPattern}");
                }
            }
        }

        // Fall back to legacy path prefix configuration
        else if (configuration.RootPathFilter != null && !string.IsNullOrWhiteSpace(configuration.RootPathFilter.Value))
        {
            skipValidation = false;
            validPaths = new HashSet<string>();
            var relativeRootPaths = configuration.RootPathFilter.Value.Split(';');

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
