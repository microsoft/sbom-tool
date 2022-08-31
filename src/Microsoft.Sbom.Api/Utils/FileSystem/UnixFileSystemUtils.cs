// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Mono.Unix;
using Mono.Unix.Native;

namespace Microsoft.Sbom.Api.Utils.FileSystem
{
    internal class UnixFileSystemUtils : FileSystemUtils
    {
        override public bool DirectoryHasReadPermissions(string directoryPath)
        {
            var directoryInfo = new UnixDirectoryInfo(directoryPath);
            return directoryInfo.CanAccess(AccessModes.R_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
        }

        override public bool DirectoryHasWritePermissions(string directoryPath)
        {
            var directoryInfo = new UnixDirectoryInfo(directoryPath);
            return directoryInfo.CanAccess(AccessModes.W_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
        }
    }
}
