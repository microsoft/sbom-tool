using System.IO;

namespace Microsoft.Sbom.Parser;

internal ref struct SbomPackageParser
{
    private readonly Stream stream;

    public SbomPackageParser(Stream stream)
    {
        this.stream = stream ?? throw new System.ArgumentNullException(nameof(stream));
    }
}
