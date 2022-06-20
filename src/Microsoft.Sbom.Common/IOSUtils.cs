using System;
using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Common
{
    public interface IOSUtils
    {
        OSPlatform GetCurrentOSPlatform();
        string GetEnvironmentVariable(string variableName);
        StringComparer GetFileSystemStringComparer();

        StringComparison GetFileSystemStringComparisonType();
    }
}
