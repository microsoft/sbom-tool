using System.IO.Enumeration;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Delegates;
public class FileDelegates
{
    public delegate IList<IntegrityMethod>? IntegrityProvider(ref FileSystemEntry fileSystemEntry, ILogger logger);
}
