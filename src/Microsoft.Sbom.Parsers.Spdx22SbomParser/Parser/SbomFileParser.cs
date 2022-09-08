using Microsoft.Sbom.Contracts;
using System.IO;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses <see cref="SBOMFile"/> object from a 'files' array.
/// </summary>
internal ref struct SbomFileParser
{
    private byte[] buffer;
    private Stream stream;

    public SbomFileParser(byte[] buffer, Stream stream)
    {
        this.buffer = buffer ?? throw new System.ArgumentNullException(nameof(buffer));
        this.stream = stream ?? throw new System.ArgumentNullException(nameof(stream));
    }

    public bool GetSbomFile(out SBOMFile sbomFile)
    {
        sbomFile = null;
        return false;
    }

}
