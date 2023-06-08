using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Spdx3_0.Software;

namespace Microsoft.Sbom.Interfaces;
public interface ISourceProvider
{
    IAsyncEnumerable<SoftwareArtifact> Get();

    SourceType SourceType { get; }
}
