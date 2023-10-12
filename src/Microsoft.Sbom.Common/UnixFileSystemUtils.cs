// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System.IO;

#if NET6_0
using Mono.Unix;
using Mono.Unix.Native;
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
#endif

#if NET8_0_OR_GREATER
    public override bool DirectoryHasReadPermissions(string directoryPath)
    {
        var fileMode = File.GetUnixFileMode(directoryPath);
        return fileMode == (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.UserRead);
    }

    public override bool DirectoryHasWritePermissions(string directoryPath)
    {
        var fileMode = File.GetUnixFileMode(directoryPath);
        return fileMode == (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite | UnixFileMode.UserWrite);
    }
#endif

}
