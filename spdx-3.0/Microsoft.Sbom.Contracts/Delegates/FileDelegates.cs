using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Delegates;
public class FileDelegates
{
    public delegate Task<IList<IntegrityMethod>?> IntegrityProvider(Stream stream, ILogger logger);
}
