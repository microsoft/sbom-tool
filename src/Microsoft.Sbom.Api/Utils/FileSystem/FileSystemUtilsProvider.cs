// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using Microsoft.Sbom.Common;
using Ninject.Activation;

namespace Microsoft.Sbom.Api.Utils.FileSystem
{
    /// <summary>
    /// Provides the <see cref="IFileSystemUtils"/> for a given OS.
    /// </summary>
    public class FileSystemUtilsProvider : Provider<IFileSystemUtils>
    {
        public FileSystemUtilsProvider()
        {
        }

        /// <summary>
        /// Checks the OS to provide the correct <see cref="IFileSystemUtils"/>.
        /// This is important due to the different file systems of operating systems.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected override IFileSystemUtils CreateInstance(IContext context)
        {
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            if (isWindows)
            {
                return new FileSystemUtils();
            }

            return new UnixFileSystemUtils();
        }
    }
}
