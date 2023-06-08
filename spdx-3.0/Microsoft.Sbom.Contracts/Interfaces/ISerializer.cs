namespace Microsoft.Sbom.Interfaces;
public interface ISerializer : IDisposable
{
    void Start();

    void EndDocument();
    
    void Serialize<T>(T obj);
}
