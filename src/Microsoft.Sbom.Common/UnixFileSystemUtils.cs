// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

#if NET6_0
using Mono.Unix;
using Mono.Unix.Native;
#elif NET8_0_OR_GREATER
using System.IO;
#endif

/// <summary>
/// Wrapper around file system functions. Used for unit testing.
/// Unix implementation.
/// </summary>
internal class UnixFileSystemUtils : FileSystemUtils
{
#if NET6_0
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

#elif NET8_0_OR_GREATER
    public override bool DirectoryHasReadPermissions(string directoryPath)
    {
        var fileMode = File.GetUnixFileMode(directoryPath);

        if (fileMode.HasFlag(UnixFileMode.GroupRead) | fileMode.HasFlag(UnixFileMode.UserRead) | fileMode.HasFlag(UnixFileMode.OtherRead))
        {
            return true;
        }

        return false;
    }

    public override bool DirectoryHasWritePermissions(string directoryPath)
    {
        var fileMode = File.GetUnixFileMode(directoryPath);

        if (fileMode.HasFlag(UnixFileMode.GroupWrite) | fileMode.HasFlag(UnixFileMode.UserWrite) | fileMode.HasFlag(UnixFileMode.OtherWrite))
        {
            return true;
        }

        return false;
    }
#endif

}
