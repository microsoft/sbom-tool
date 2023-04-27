// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;

namespace Microsoft.Sbom.Common;

/// <summary>
/// A wrapper class to make the filesystem methods unit testable.
/// </summary>
public abstract class FileSystemUtils : IFileSystemUtils
{
    private readonly EnumerationOptions dontFollowSymlinks = new EnumerationOptions
    {
        AttributesToSkip = FileAttributes.ReparsePoint
    };

    private static readonly string SbomToolTempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    private const string SearchAllFilesAndFolders = "*";

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public string GetSbomToolTempPath() => SbomToolTempPath;

    public IEnumerable<string> GetDirectories(string path, bool followSymlinks = true) => followSymlinks switch
    {
        true => Directory.GetDirectories(path),
        false => Directory.GetDirectories(path, SearchAllFilesAndFolders, dontFollowSymlinks)
    };

    public IEnumerable<string> GetFilesInDirectory(string path, bool followSymlinks = true) => followSymlinks switch
    {
        true => Directory.GetFiles(path),
        false => Directory.GetFiles(path, SearchAllFilesAndFolders, dontFollowSymlinks)
    };

    public DirectorySecurity GetDirectorySecurity(string directoryPath) => new DirectoryInfo(directoryPath).GetAccessControl();

    public string JoinPaths(string root, string relativePath) => Path.Join(root, relativePath);

    public string JoinPaths(string root, string relativePath, string secondRelativePath) => Path.Join(root, relativePath, secondRelativePath);

    /// <inheritdoc/>
    public string GetRelativePath(string relativeTo, string path) => Path.GetRelativePath(relativeTo, path);

    public string GetDirectoryName(string filePath) => Path.GetDirectoryName(filePath);

    public Stream OpenRead(string filePath) => File.OpenRead(filePath);

    public string ReadAllText(string filePath) => File.ReadAllText(filePath);

    public bool FileExists(string path) => File.Exists(path);

    public Stream OpenWrite(string filePath) => new FileStream(
        filePath,
        FileMode.Create,
        FileAccess.Write,
        FileShare.Delete,
        Constants.DefaultStreamBufferSize,
        FileOptions.Asynchronous);

    abstract public bool DirectoryHasReadPermissions(string directoryPath);

    abstract public bool DirectoryHasWritePermissions(string directoryPath);

    public DirectoryInfo CreateDirectory(string path) => Directory.CreateDirectory(path);

    public void DeleteFile(string filePath) => File.Delete(filePath);

    public void DeleteDir(string path, bool recursive = false) => Directory.Delete(path, recursive);

    public string AbsolutePath(string filePath) => Path.GetFullPath(filePath);

    /// <inheritdoc/>
    public bool IsDirectoryEmpty(string directoryPath) => DirectoryExists(directoryPath) && !Directory.EnumerateFiles(directoryPath).Any();
}