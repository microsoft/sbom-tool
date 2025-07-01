// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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

        // Normalize the file path
        var normalizedFilePath = Path.GetFullPath(filePath);

        // If basePath is provided and pattern is relative, create the full pattern
        string normalizedPattern;
        if (!string.IsNullOrEmpty(basePath) && !Path.IsPathRooted(pattern))
        {
            var combinedPath = Path.Combine(basePath, pattern);
            normalizedPattern = Path.GetFullPath(combinedPath);
        }
        else
        {
            normalizedPattern = pattern;
        }

        // Convert glob pattern to regex
        var regexPattern = ConvertGlobToRegex(normalizedPattern);

        // Perform case-insensitive matching for cross-platform compatibility
        var regex = new Regex(regexPattern, RegexOptions.IgnoreCase);

        return regex.IsMatch(normalizedFilePath);
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
                        regexPattern.Append(".*"); // ** matches any characters including path separators
                        i++; // Skip the second *
                    }
                    else
                    {
                        regexPattern.Append(@"[^\\\/]*"); // * matches any characters except path separators
                    }

                    break;

                case '?':
                    regexPattern.Append('.'); // ? matches any single character
                    break;

                case '\\':
                case '/':
                    regexPattern.Append(@"[\\\/]"); // Allow both \ and / as path separators
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

        // Anchor the pattern to match from the beginning
        return "^" + regexPattern.ToString() + ".*$";
    }
}
