using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom.JsonSerializer;
public class Spdx3JsonSerializer : ISerializer
{
    private readonly ILogger logger;
    private readonly string filePath;

    private Utf8JsonWriter jsonWriter;
    private Stream stream;

    private bool disposedValue;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Spdx3JsonSerializer(string filePath, ILogger? logger = null)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    {
        this.logger = logger ?? NullLogger.Instance;
        this.filePath = filePath;
    }

    public void EndDocument()
    {
        jsonWriter.WriteEndArray();
        jsonWriter.WriteEndObject();
    }

    public void Serialize<T>(T obj)
    {
        System.Text.Json.JsonSerializer.Serialize(jsonWriter, obj);
       // jsonWriter.w System.Text.Json.JsonSerializer.Serialize(obj);
    }

    public void Start()
    {
        this.stream = File.Create(this.filePath);
        this.jsonWriter = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        
        jsonWriter.WriteStartObject();
        jsonWriter.WritePropertyName(JsonEncodedText.Encode("@context"));
        jsonWriter.WriteStringValue(JsonEncodedText.Encode("https://spdx.github.io/spdx-3-model/rdf/context.json"));
        jsonWriter.WriteStartArray(JsonEncodedText.Encode("@graph"));

        jsonWriter.Flush();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                this.jsonWriter?.Dispose();
                this.stream?.Dispose();
            }

            disposedValue = true;
        }
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
