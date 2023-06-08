using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Interfaces;
public interface ISerializer : IDisposable
{
    void Start();

    void EndDocument();
    
    void Serialize(Element obj, Type type);
}
