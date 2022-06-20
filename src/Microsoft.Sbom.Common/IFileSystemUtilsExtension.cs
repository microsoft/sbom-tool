// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common
{
    /// <summary>
    /// FileSystemUtilsExtension class uses FileSystemUtils class to run additional more complex
    /// file system logic that can be reused.
    /// </summary>
    public interface IFileSystemUtilsExtension
    {
        /// <summary>
        /// Determines if the targetPath is a child of the sourcePath.
        /// </summary>
        bool IsTargetPathInSource(string targetPath, string sourcePath);
    }
}
