using System.IO.Enumeration;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.File;
public class Delegates
{
    public delegate IList<IntegrityMethod>? IntegrityProvider(ref FileSystemEntry fileSystemEntry, ILogger logger);
}
