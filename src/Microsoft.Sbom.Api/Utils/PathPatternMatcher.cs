// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// Provides pattern matching functionality for file paths using glob-style patterns.
/// </summary>
public static class PathPatternMatcher
{
    /// <summary>
    /// Checks if a file path matches a glob-style pattern.
    /// Supports * (single level wildcard) and ** (recursive wildcard).
    /// </summary>
    /// <param name="filePath">The file path to check.</param>
    /// <param name="pattern">The glob pattern to match against.</param>
    /// <param name="basePath">The base path to resolve relative patterns.</param>
    /// <returns>True if the path matches the pattern, false otherwise.</returns>
    public static bool IsMatch(string filePath, string pattern, string basePath = null)
    {
        if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(pattern))
        {
            return false;
        }

        // Normalize path separators for cross-platform compatibility
        var normalizedFilePath = NormalizePath(filePath);
        var normalizedBasePath = !string.IsNullOrEmpty(basePath) ? NormalizePath(basePath) : null;
        var normalizedPattern = NormalizePath(pattern);

        // If basePath is provided and pattern is relative, we need to match against the relative portion
        string pathToMatch;
        if (!string.IsNullOrEmpty(normalizedBasePath) && !Path.IsPathRooted(normalizedPattern))
        {
            // Check if the file is within the base path
            if (!normalizedFilePath.StartsWith(normalizedBasePath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Get the relative path from the base path
            var relativePath = GetRelativePath(normalizedBasePath, normalizedFilePath);
            pathToMatch = relativePath;
        }
        else
        {
            pathToMatch = normalizedFilePath;
        }

        // Convert glob pattern to regex
        var regexPattern = ConvertGlobToRegex(normalizedPattern);

        // Perform case-insensitive matching for cross-platform compatibility
        var regex = new Regex(regexPattern, RegexOptions.IgnoreCase);

        return regex.IsMatch(pathToMatch);
    }

    /// <summary>
    /// Normalizes path separators for cross-platform compatibility.
    /// </summary>
    /// <param name="path">The path to normalize.</param>
    /// <returns>A normalized path with consistent separators.</returns>
    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path;
        }

        // Replace all path separators with the standard forward slash for internal processing
        return path.Replace('\\', '/');
    }

    /// <summary>
    /// Gets the relative path from a base path to a target path.
    /// </summary>
    /// <param name="basePath">The base path.</param>
    /// <param name="targetPath">The target path.</param>
    /// <returns>The relative path from base to target.</returns>
    private static string GetRelativePath(string basePath, string targetPath)
    {
        if (string.IsNullOrEmpty(basePath) || string.IsNullOrEmpty(targetPath))
        {
            return targetPath;
        }

        // Ensure base path ends with separator for proper prefix matching
        if (!basePath.EndsWith("/", StringComparison.Ordinal) && !basePath.EndsWith("\\", StringComparison.Ordinal))
        {
            basePath += "/";
        }

        // If target starts with base path, return the remainder
        if (targetPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
        {
            return targetPath.Substring(basePath.Length);
        }

        return targetPath;
    }

    /// <summary>
    /// Converts a glob pattern to a regular expression.
    /// </summary>
    /// <param name="globPattern">The glob pattern to convert.</param>
    /// <returns>A regular expression string.</returns>
    private static string ConvertGlobToRegex(string globPattern)
    {
        // Start building the regex pattern
        var regexPattern = new System.Text.StringBuilder();

        for (var i = 0; i < globPattern.Length; i++)
        {
            var c = globPattern[i];

            switch (c)
            {
                case '*':
                    // Check for ** pattern
                    if (i + 1 < globPattern.Length && globPattern[i + 1] == '*')
                    {
                        // Look ahead to see if ** is followed by a path separator
                        if (i + 2 < globPattern.Length && (globPattern[i + 2] == '/' || globPattern[i + 2] == '\\'))
                        {
                            // **/ means zero or more directories followed by /
                            regexPattern.Append("(?:[^/]+/)*");
                            i += 2; // Skip the second * and the /
                        }
                        else
                        {
                            // ** at end or followed by non-separator
                            regexPattern.Append(".*");
                            i++; // Skip the second *
                        }
                    }
                    else
                    {
                        regexPattern.Append(@"[^/]*"); // * matches any characters except path separators
                    }

                    break;

                case '?':
                    regexPattern.Append('.'); // ? matches any single character
                    break;

                case '\\':
                case '/':
                    regexPattern.Append('/'); // Use forward slash consistently
                    break;

                default:
                    // Escape special regex characters
                    if ("()[]{}^$+.|".Contains(c))
                    {
                        regexPattern.Append('\\');
                    }

                    regexPattern.Append(c);
                    break;
            }
        }

        // Don't anchor to end with .* since we want exact path matching
        return "^" + regexPattern.ToString() + "$";
    }
}
