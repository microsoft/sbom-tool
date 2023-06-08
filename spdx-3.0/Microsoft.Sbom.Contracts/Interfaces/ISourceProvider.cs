using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Software;

namespace Microsoft.Sbom.Interfaces;
public interface ISourceProvider<T> 
    where T : SoftwareArtifact
{
    IAsyncEnumerable<T> Get();

    SourceType SourceType { get; }
}
