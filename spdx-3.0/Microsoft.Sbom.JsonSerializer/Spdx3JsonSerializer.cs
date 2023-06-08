using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom.JsonSerializer;
public class Spdx3JsonSerializer : ISerializer
{
    private readonly ILogger logger;
    private readonly string filePath;
    private FileStream stream;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Spdx3JsonSerializer(string filePath, ILogger? logger = null)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    {
        this.logger = logger;
        this.filePath = filePath;
    }

    public void EndDocument()
    {
    }

    public void Serialize<T>(T obj)
    {
        System.Text.Json.JsonSerializer.Serialize(this.stream, obj);
    }

    public IDisposable Start()
    {
        this.stream = File.Create(this.filePath);
        return this.stream;
    }
}
