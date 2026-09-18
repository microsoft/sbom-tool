// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Extensions.FileSystemGlobbing;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// Provides pattern matching functionality for file paths using glob-style patterns.
/// Leverages .NET's built-in Microsoft.Extensions.FileSystemGlobbing for robust cross-platform support.
///
/// Supported patterns:
/// - * matches zero or more characters (excluding directory separators)
/// - ** matches zero or more characters (including directory separators)
///
/// Note: The ? wildcard for single character matching is not supported by the underlying .NET implementation.
/// </summary>
public static class PathPatternMatcher
{
    /// <summary>
    /// Checks if a file path matches a glob-style pattern.
    /// Uses .NET's built-in globbing which supports * and ** patterns but not ? for single character matching.
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

        try
        {
            // Normalize paths for cross-platform compatibility
            var normalizedFilePath = NormalizePath(filePath);
            var normalizedPattern = NormalizePath(pattern);

            // Use case-insensitive matching for cross-platform compatibility
            var matcher = new Matcher(StringComparison.OrdinalIgnoreCase);
            matcher.AddInclude(normalizedPattern);

            // Determine the path to match against
            string pathToMatch;
            if (!string.IsNullOrEmpty(basePath) && !Path.IsPathRooted(normalizedPattern))
            {
                // For relative patterns with base path, get the relative path
                if (!IsPathWithinBase(normalizedFilePath, basePath))
                {
                    return false;
                }

                pathToMatch = GetRelativePath(basePath, normalizedFilePath);
            }
            else
            {
                // For absolute patterns or no base path, use the normalized full path
                pathToMatch = normalizedFilePath;
            }

            // Use the matcher to check if the path matches the pattern
            var result = matcher.Match(pathToMatch);
            return result.HasMatches;
        }
        catch
        {
            // If any exception occurs during matching, return false
            return false;
        }
    }

    /// <summary>
    /// Checks if a file path is within the specified base path.
    /// </summary>
    /// <param name="filePath">The file path to check.</param>
    /// <param name="basePath">The base path.</param>
    /// <returns>True if the file path is within the base path, false otherwise.</returns>
    private static bool IsPathWithinBase(string filePath, string basePath)
    {
        try
        {
            // Normalize paths for cross-platform compatibility
            var normalizedFilePath = NormalizePath(filePath);
            var normalizedBasePath = NormalizePath(basePath);

            // For Windows-style paths on non-Windows systems, use manual comparison
            if (IsWindowsStylePath(normalizedBasePath) && IsWindowsStylePath(normalizedFilePath))
            {
                var normalizedBase = normalizedBasePath.TrimEnd('/') + "/";
                return normalizedFilePath.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase);
            }

            // Use Path.GetFullPath for proper platform-specific handling
            var fullFilePath = Path.GetFullPath(normalizedFilePath);
            var fullBasePath = Path.GetFullPath(normalizedBasePath);

            // Ensure base path ends with separator for proper prefix check
            if (!fullBasePath.EndsWith(Path.DirectorySeparatorChar) &&
                !fullBasePath.EndsWith(Path.AltDirectorySeparatorChar))
            {
                fullBasePath += Path.DirectorySeparatorChar;
            }

            return fullFilePath.StartsWith(fullBasePath, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Fallback: manual comparison with normalized paths
            var normalizedFilePath = NormalizePath(filePath);
            var normalizedBasePath = NormalizePath(basePath).TrimEnd('/') + "/";
            return normalizedFilePath.StartsWith(normalizedBasePath, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Gets the relative path from a base path to a target path.
    /// </summary>
    /// <param name="basePath">The base path.</param>
    /// <param name="targetPath">The target path.</param>
    /// <returns>The relative path from base to target.</returns>
    private static string GetRelativePath(string basePath, string targetPath)
    {
        try
        {
            // Normalize paths for cross-platform compatibility
            var normalizedBasePath = NormalizePath(basePath);
            var normalizedTargetPath = NormalizePath(targetPath);

            // For cross-platform compatibility, handle Windows-style paths manually
            if (IsWindowsStylePath(normalizedBasePath) && IsWindowsStylePath(normalizedTargetPath))
            {
                return GetRelativePathManual(normalizedBasePath, normalizedTargetPath);
            }

            // Use Path.GetRelativePath for Unix-style or when both paths are in the same format
            var fullBasePath = Path.GetFullPath(normalizedBasePath);
            var fullTargetPath = Path.GetFullPath(normalizedTargetPath);
            return Path.GetRelativePath(fullBasePath, fullTargetPath);
        }
        catch
        {
            // Fallback: manual calculation
            return GetRelativePathManual(basePath, targetPath);
        }
    }

    /// <summary>
    /// Normalizes a path by converting backslashes to forward slashes.
    /// </summary>
    /// <param name="path">The path to normalize.</param>
    /// <returns>The normalized path.</returns>
    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path;
        }

        return path.Replace('\\', '/');
    }

    /// <summary>
    /// Checks if a path is in Windows style (has a drive letter).
    /// </summary>
    /// <param name="path">The path to check.</param>
    /// <returns>True if the path is Windows-style, false otherwise.</returns>
    private static bool IsWindowsStylePath(string path)
    {
        return !string.IsNullOrEmpty(path) &&
               path.Length >= 2 &&
               char.IsLetter(path[0]) &&
               path[1] == ':';
    }

    /// <summary>
    /// Manually calculates relative path for cross-platform compatibility.
    /// </summary>
    /// <param name="basePath">The base path.</param>
    /// <param name="targetPath">The target path.</param>
    /// <returns>The relative path.</returns>
    private static string GetRelativePathManual(string basePath, string targetPath)
    {
        if (string.IsNullOrEmpty(basePath) || string.IsNullOrEmpty(targetPath))
        {
            return targetPath;
        }

        var normalizedBase = NormalizePath(basePath).TrimEnd('/') + "/";
        var normalizedTarget = NormalizePath(targetPath);

        if (normalizedTarget.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase))
        {
            return normalizedTarget.Substring(normalizedBase.Length);
        }

        return normalizedTarget;
    }
}
