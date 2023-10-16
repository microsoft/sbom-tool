// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// A wrapper class to make the filesystem methods unit testable.
/// </summary>
public abstract class FileSystemUtils : IFileSystemUtils
{
    private const string SearchAllFilesAndFolders = "*";

    private static readonly string SbomToolTempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    private readonly EnumerationOptions dontFollowSymlinks = new()
    {
        AttributesToSkip = FileAttributes.ReparsePoint,
    };

    /// <inheritdoc />
    public bool DirectoryExists(string path) => Directory.Exists(path);

    /// <inheritdoc />
    public string GetSbomToolTempPath() => SbomToolTempPath;

    /// <inheritdoc />
    public IEnumerable<string> GetDirectories(string path, bool followSymlinks = true) => followSymlinks switch
    {
        true => Directory.GetDirectories(path),
        false => Directory.GetDirectories(path, SearchAllFilesAndFolders, this.dontFollowSymlinks),
    };

    /// <inheritdoc />
    public IEnumerable<string> GetFilesInDirectory(string path, bool followSymlinks = true) => followSymlinks switch
    {
        true => Directory.GetFiles(path),
        false => Directory.GetFiles(path, SearchAllFilesAndFolders, this.dontFollowSymlinks)
    };

    /// <inheritdoc />
    public string JoinPaths(string root, string relativePath) => Path.Join(root, relativePath);

    /// <inheritdoc />
    public string JoinPaths(string root, string relativePath, string secondRelativePath) =>
        Path.Join(root, relativePath, secondRelativePath);

    /// <inheritdoc />
    /// <inheritdoc />
    public string GetRelativePath(string relativeTo, string path) => Path.GetRelativePath(relativeTo, path);

    /// <inheritdoc />
    public string GetDirectoryName(string filePath) => Path.GetDirectoryName(filePath);

    /// <inheritdoc />
    public Stream OpenRead(string filePath) => File.OpenRead(filePath);

    /// <inheritdoc />
    public string ReadAllText(string filePath) => File.ReadAllText(filePath);

    /// <inheritdoc />
    public void WriteAllText(string filePath, string contents) => File.WriteAllText(filePath, contents);

    /// <inheritdoc />
    public bool FileExists(string path) => File.Exists(path);

    /// <inheritdoc />
    public Stream OpenWrite(string filePath) => new FileStream(
        filePath,
        FileMode.Create,
        FileAccess.Write,
        FileShare.Delete,
        Constants.DefaultStreamBufferSize,
        FileOptions.Asynchronous);

    /// <inheritdoc />
    public abstract bool DirectoryHasReadPermissions(string directoryPath);

    /// <inheritdoc />
    public abstract bool DirectoryHasWritePermissions(string directoryPath);

    /// <inheritdoc />
    public DirectoryInfo CreateDirectory(string path) => Directory.CreateDirectory(path);

    /// <inheritdoc />
    public void DeleteFile(string filePath) => File.Delete(filePath);

    /// <inheritdoc />
    public void DeleteDir(string path, bool recursive = false) => Directory.Delete(path, recursive);

    /// <inheritdoc />
    public string AbsolutePath(string filePath) => Path.GetFullPath(filePath);

    /// <inheritdoc />
    public bool IsDirectoryEmpty(string directoryPath) =>
        this.DirectoryExists(directoryPath) && !Directory.EnumerateFiles(directoryPath).Any();

    /// <inheritdoc />
    public string GetFullPath(string path) => Path.GetFullPath(path);

    /// <inheritdoc />
    public DirectoryInfo GetParentDirectory(string path) => Directory.GetParent(path);
}
