

using Mono.Unix;
using Mono.Unix.Native;

namespace Microsoft.Sbom.Common
{
    class UnixFileSystemUtils : FileSystemUtils
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
