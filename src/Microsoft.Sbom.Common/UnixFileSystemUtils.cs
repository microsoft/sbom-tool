// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using Mono.Unix;
using Mono.Unix.Native;

/// <summary>
/// Wrapper around file system functions. Used for unit testing.
/// Unix implementation.
/// </summary>
internal class UnixFileSystemUtils : FileSystemUtils
{
    /// <inheritdoc />
    public override bool DirectoryHasReadPermissions(string directoryPath)
    {
        var directoryInfo = new UnixDirectoryInfo(directoryPath);
        return directoryInfo.CanAccess(AccessModes.R_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
    }

    /// <inheritdoc />
    public override bool DirectoryHasWritePermissions(string directoryPath)
    {
        var directoryInfo = new UnixDirectoryInfo(directoryPath);
        return directoryInfo.CanAccess(AccessModes.W_OK) && directoryInfo.CanAccess(AccessModes.F_OK);
    }
}
