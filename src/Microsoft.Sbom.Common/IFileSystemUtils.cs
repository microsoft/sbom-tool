using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;

namespace Microsoft.Sbom.Common
{
    /// <summary>
    /// Wrapper around file system functions. Used for unit testing.
    /// </summary>
    public interface IFileSystemUtils
    {
        bool DirectoryExists(string path);
        DirectoryInfo CreateDirectory(string path);
        IEnumerable<string> GetFilesInDirectory(string path, bool followSymlinks = true);
        IEnumerable<string> GetDirectories(string path, bool followSymlinks = true);
        Stream OpenRead(string filePath);
        Stream OpenWrite(string filePath);
        string ReadAllText(string filePath);
        string JoinPaths(string root, string relativePath);

        string JoinPaths(string root, string relativePath, string secondRelativePath);

        /// <summary>
        /// Create a relative path from one path to another. Paths will be resolved before calculating the difference.
        /// Default path comparison for the active platform will be used (OrdinalIgnoreCase for Windows or Mac, Ordinal for Unix).
        /// </summary>
        /// <param name="relativeTo">The source path the output should be relative to. This path is always considered to be a directory.</param>
        /// <param name="path">The destination path.</param>
        /// <returns>The relative path or <paramref name="path"/> if the paths don't share the same root.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="relativeTo"/> or <paramref name="path"/> is <c>null</c> or an empty string.</exception>
        string GetRelativePath(string relativeTo, string path);

        bool FileExists(string path);
        string GetDirectoryName(string filePath);
        DirectorySecurity GetDirectorySecurity(string directoryPath);
        bool DirectoryHasReadPermissions(string directoryPath);
        bool DirectoryHasWritePermissions(string directoryPath);
        void DeleteFile(string filePath);
        /// <summary>
        /// Delete a directory.
        /// </summary>
        /// <param name="path">The absolute path of the directory.</param>
        /// <param name="recursive">Delete directory contents recursively.</param>
        void DeleteDir(string path, bool recursive = false);

        string AbsolutePath(string filePath);

        /// <summary>
        /// Returns whether a directory is empty.
        /// </summary>
        bool IsDirectoryEmpty(string directoryPath);
    }
}
