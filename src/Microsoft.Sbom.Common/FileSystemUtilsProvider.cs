// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Common;

/// <summary>
/// Provides the <see cref="IFileSystemUtils"/> for a given OS.
/// </summary>
public static class FileSystemUtilsProvider
{
    /// <summary>
    /// Checks the OS to provide the correct <see cref="IFileSystemUtils"/>.
    /// This is important due to the different file systems of operating systems.
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public static IFileSystemUtils CreateInstance()
    {
        var isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        return isWindows ? new WindowsFileSystemUtils() : new UnixFileSystemUtils();
    }
}
