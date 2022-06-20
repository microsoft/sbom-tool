using System.Runtime.InteropServices;
using Ninject.Activation;

namespace Microsoft.Sbom.Common
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
