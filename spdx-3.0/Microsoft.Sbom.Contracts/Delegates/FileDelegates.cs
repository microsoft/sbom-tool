using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;

namespace Microsoft.Sbom.Delegates;
public class FileDelegates
{
    public delegate Task<IList<FileHash>?> IntegrityProvider(Stream stream, ILogger logger);
}
