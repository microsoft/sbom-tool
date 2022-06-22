// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common;
using Ninject;
using System;

namespace Microsoft.Sbom.Common.Extensions
{
    /// <summary>
    /// FileSystemUtilsExtension class uses FileSystemUtils class to run additional more complex
    /// file system logic that can be reused.
    /// </summary>
    public class FileSystemUtilsExtension : IFileSystemUtilsExtension
    {
        [Inject]
        public IFileSystemUtils FileSystemUtils { get; set; }

        [Inject]
        public IOSUtils OsUtils { get; set; }

        /// <summary>
        /// Determines if the targetPath is a child of the sourcePath.
        /// </summary>
        public bool IsTargetPathInSource(string targetPath, string sourcePath)
        {
            if (targetPath == null)
            {
                throw new ArgumentNullException(nameof(targetPath));
            }

            if (sourcePath == null)
            {
                throw new ArgumentNullException(nameof(sourcePath));
            }

            // Sanitize the paths before comparison.
            var sanitizedPath = FileSystemUtils.AbsolutePath(targetPath);
            var sanitizedSourcePath = FileSystemUtils.AbsolutePath(sourcePath);
            return sanitizedPath.StartsWith(sanitizedSourcePath, OsUtils.GetFileSystemStringComparisonType());
        }
    }
}
