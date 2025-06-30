// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

/// <summary>
/// Wrapper around file system functions. Used for unit testing.
/// </summary>
public interface IFileSystemUtils
{
    /// <summary>
    /// Returns whether a directory exists.
    /// </summary>
    /// <param name="path">The absolute path of the directory.</param>
    /// <returns>True if the directory exists, false otherwise.</returns>
    public bool DirectoryExists(string path);

    /// <summary>
    /// Create a directory.
    /// </summary>
    /// <param name="path">The absolute path of the directory.</param>
    /// <returns>The created directory.</returns>
    public DirectoryInfo CreateDirectory(string path);

    /// <summary>
    /// List all files in a directory.
    /// </summary>
    /// <param name="path">The absolute path of the directory.</param>
    /// <param name="followSymlinks">Whether to follow symlinks.</param>
    /// <returns>A list of files in the directory.</returns>
    public IEnumerable<string> GetFilesInDirectory(string path, bool followSymlinks = true);

    /// <summary>
    /// List all directories in a directory.
    /// </summary>
    /// <param name="path">The absolute path of the directory.</param>
    /// <param name="followSymlinks">Whether to follow symlinks.</param>
    /// <returns>A list of directories in the directory.</returns>
    public IEnumerable<string> GetDirectories(string path, bool followSymlinks = true);

    /// <summary>
    /// Open a file for reading.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The opened file.</returns>
    public Stream OpenRead(string filePath);

    /// <summary>
    /// Open a file for writing.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The opened file.</returns>
    public Stream OpenWrite(string filePath);

    /// <summary>
    /// Read all text from a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The contents of the file.</returns>
    public string ReadAllText(string filePath);

    /// <summary>
    /// Read all text asynchronously from a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The contents of the file.</returns>
    public Task<string> ReadAllTextAsync(string filePath);

    /// <summary>
    /// Write all text to a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <param name="contents">The contents to write.</param>
    public void WriteAllText(string filePath, string contents);

    /// <summary>
    /// Join two paths.
    /// </summary>
    /// <param name="root">The root path.</param>
    /// <param name="relativePath">The relative path.</param>
    /// <returns>The joined path.</returns>
    public string JoinPaths(string root, string relativePath);

    /// <summary>
    /// Join three paths.
    /// </summary>
    /// <param name="root">The root path.</param>
    /// <param name="relativePath">The relative path.</param>
    /// <param name="secondRelativePath">The second relative path.</param>
    /// <returns>The joined path.</returns>
    public string JoinPaths(string root, string relativePath, string secondRelativePath);

    /// <summary>
    /// Create a relative path from one path to another. Paths will be resolved before calculating the difference.
    /// Default path comparison for the active platform will be used (OrdinalIgnoreCase for Windows or Mac, Ordinal for Unix).
    /// </summary>
    /// <param name="relativeTo">The source path the output should be relative to. This path is always considered to be a directory.</param>
    /// <param name="path">The destination path.</param>
    /// <returns>The relative path or <paramref name="path"/> if the paths don't share the same root.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="relativeTo"/> or <paramref name="path"/> is <c>null</c> or an empty string.</exception>
    public string GetRelativePath(string relativeTo, string path);

    /// <summary>
    /// Returns whether a file exists.
    /// </summary>
    /// <param name="path">The absolute path of the file.</param>
    /// <returns>True if the file exists, false otherwise.</returns>
    public bool FileExists(string path);

    /// <summary>
    /// Get the file name of a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The file name.</returns>
    public string GetFileName(string filePath);

    /// <summary>
    /// Get the directory name of a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    /// <returns>The directory name.</returns>
    public string GetDirectoryName(string filePath);

    /// <summary>
    /// Check if a directory has read permissions.
    /// </summary>
    /// <param name="directoryPath">The absolute path of the directory.</param>
    /// <returns>True if the directory has read permissions, false otherwise.</returns>
    public bool DirectoryHasReadPermissions(string directoryPath);

    /// <summary>
    /// Check if a directory has write permissions.
    /// </summary>
    /// <param name="directoryPath">The absolute path of the directory.</param>
    /// <returns>True if the directory has write permissions, false otherwise.</returns>
    public bool DirectoryHasWritePermissions(string directoryPath);

    /// <summary>
    /// Delete a file.
    /// </summary>
    /// <param name="filePath">The absolute path of the file.</param>
    public void DeleteFile(string filePath);

    /// <summary>
    /// Delete a directory.
    /// </summary>
    /// <param name="path">The absolute path of the directory.</param>
    /// <param name="recursive">Delete directory contents recursively.</param>
    public void DeleteDir(string path, bool recursive = false);

    /// <summary>
    /// Get the absolute path of a file.
    /// </summary>
    /// <param name="filePath">The absolute or relative path of the file.</param>
    /// <returns>The absolute path of the file.</returns>
    public string AbsolutePath(string filePath);

    /// <summary>
    /// Returns whether a directory is empty.
    /// </summary>
    /// <returns>True if the directory is empty, false otherwise.</returns>
    public bool IsDirectoryEmpty(string directoryPath);

    /// <summary>
    /// Temporary path to be used in scenarios where a (-m) and (-di) are provided and the user does not provide a (-b) path.
    /// </summary>
    /// <returns>The temporary path.</returns>
    public string GetSbomToolTempPath();

    /// <summary>
    /// Get the full path of a file or directory.
    /// </summary>
    /// <param name="path">The absolute or relative path of the file or directory.</param>
    /// <returns>The full path of the file or directory.</returns>
    public string GetFullPath(string path);

    /// <summary>
    /// Get the parent directory of a file or directory.
    /// </summary>
    /// <param name="path">The absolute or relative path of the file or directory.</param>
    /// <returns>The parent directory.</returns>
    public DirectoryInfo GetParentDirectory(string path);

    /// <summary>
    /// Read all the content of the specified file as an array of bytes.
    /// </summary>
    /// <param name="path">The absolute relative path of a file.</param>
    /// <returns>Byte array content of the file.</returns>
    public byte[] ReadAllBytes(string path);

    /// <summary>
    /// Returns the size of the given file
    /// </summary>
    /// <param name="path">The absolute relative path of a file.</param>
    /// <returns>Size of file in bytes.</returns>
    public long GetFileSize(string path);

    /// <summary>
    /// Returns the path to a temp file
    /// </summary>
    /// <param name="fileName">The naem of the temp file.</param>
    /// <returns>Path to a temp file</returns>
    public string GetTempFile(string fileName);
}
