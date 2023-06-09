using Microsoft.Sbom.Enums;

namespace Microsoft.Sbom.Interfaces;
public interface ISourceProvider
{
    IAsyncEnumerable<object> Get();

    SourceType SourceType { get; }
}
