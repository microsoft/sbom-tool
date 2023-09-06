// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Mono.Unix;
using Mono.Unix.Native;

namespace Microsoft.Sbom.Common;

internal class UnixFileSystemUtils : FileSystemUtils
{
    public override bool DirectoryHasReadPermissions(string directoryPath)
    {
        var directoryInfo = new UnixDirectoryInfo(directoryPath);
        return directoryInfo.CanAccess(AccessModes.R_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
    }

    public override bool DirectoryHasWritePermissions(string directoryPath)
    {
        var directoryInfo = new UnixDirectoryInfo(directoryPath);
        return directoryInfo.CanAccess(AccessModes.W_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
    }
}
