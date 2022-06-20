// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;

namespace Microsoft.Sbom.Common
{
    /// <summary>
    /// A wrapper class to make the filesystem methods unit testable.
    /// </summary>
    public class FileSystemUtils : IFileSystemUtils
    {
        private readonly EnumerationOptions _dontFollowSymlinks = new EnumerationOptions
        {
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        private const string _searchAllFilesAndFolders = "*";

        public bool DirectoryExists(string path) => Directory.Exists(path);

        public IEnumerable<string> GetDirectories(string path, bool followSymlinks = true) => (followSymlinks) switch
        {
            true => Directory.GetDirectories(path),
            false => Directory.GetDirectories(path, _searchAllFilesAndFolders, _dontFollowSymlinks)
        };

        public IEnumerable<string> GetFilesInDirectory(string path, bool followSymlinks = true) => (followSymlinks) switch
        {
            true => Directory.GetFiles(path),
            false => Directory.GetFiles(path, _searchAllFilesAndFolders, _dontFollowSymlinks)
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

        public Stream OpenWrite(string filePath) => new FileStream(filePath,
                                FileMode.Create,
                                FileAccess.Write,
                                FileShare.Delete,
                                Constants.DefaultStreamBufferSize,
                                FileOptions.Asynchronous);

        virtual public bool DirectoryHasReadPermissions(string directoryPath)
        {
            try
            {
                var readAllow = false;
                var readDeny = false;
                var accessControlList = GetDirectorySecurity(directoryPath);
                if (accessControlList == null)
                    return false;

                //get the access rules that pertain to a valid SID/NTAccount.
                var accessRules = accessControlList.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                if (accessRules == null)
                    return false;

                //we want to go over these rules to ensure a valid SID has access
                foreach (FileSystemAccessRule rule in accessRules)
                {
                    if ((FileSystemRights.Read & rule.FileSystemRights) != FileSystemRights.Read)
                        continue;

                    if (rule.AccessControlType == AccessControlType.Allow)
                        readAllow = true;
                    else if (rule.AccessControlType == AccessControlType.Deny)
                        readDeny = true;
                }

                return readAllow && !readDeny;
            }
            catch (Exception)
            {
                // TODO Add logger with debug
                return false;
            }
        }

        virtual public bool DirectoryHasWritePermissions(string directoryPath)
        {
            try
            {
                var writeAllow = false;
                var writeDeny = false;
                var accessControlList = GetDirectorySecurity(directoryPath);
                if (accessControlList == null)
                    return false;
                var accessRules = accessControlList.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                if (accessRules == null)
                    return false;

                foreach (FileSystemAccessRule rule in accessRules)
                {
                    if ((FileSystemRights.Write & rule.FileSystemRights) != FileSystemRights.Write)
                        continue;

                    if (rule.AccessControlType == AccessControlType.Allow)
                        writeAllow = true;
                    else if (rule.AccessControlType == AccessControlType.Deny)
                        writeDeny = true;
                }

                return writeAllow && !writeDeny;
            }
            catch (Exception)
            {
                // TODO Add logger with debug
                return false;
            }
        }

        public DirectoryInfo CreateDirectory(string path) => Directory.CreateDirectory(path);

        public void DeleteFile(string filePath) => File.Delete(filePath);

        public void DeleteDir(string path, bool recursive = false) => Directory.Delete(path, recursive);

        public string AbsolutePath(string filePath) => Path.GetFullPath(filePath);

        /// <inheritdoc/>
        public bool IsDirectoryEmpty(string directoryPath) => DirectoryExists(directoryPath) && !Directory.EnumerateFiles(directoryPath).Any();

    }
}
