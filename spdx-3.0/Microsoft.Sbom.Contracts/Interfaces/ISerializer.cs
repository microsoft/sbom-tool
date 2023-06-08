namespace Microsoft.Sbom.Interfaces;
public interface ISerializer
{
    IDisposable Start();

    void EndDocument();
    
    void Serialize<T>(T obj);
}
