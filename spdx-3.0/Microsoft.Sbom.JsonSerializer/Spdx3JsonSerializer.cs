using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Converters;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.JsonSerializer;
public class Spdx3JsonSerializer : ISerializer
{
    private readonly ILogger logger;
    private readonly string filePath;
    private readonly Utf8JsonWriter jsonWriter;
    private readonly Stream stream;
    private readonly JsonSerializerOptions jsonOptions;

    private bool disposedValue;

    public Spdx3JsonSerializer(Configuration? configuration)
    {
        this.logger = configuration?.Logger ?? NullLogger.Instance;
        this.filePath = configuration?.OutputFilePath ?? Path.Combine(Path.GetTempPath(), $"sbom-{Guid.NewGuid()}.json");
        this.logger.LogDebug("Writing SBOM to {filePath}", filePath);
        this.stream = File.Create(this.filePath);
        this.jsonOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters =
            {
                new JsonStringEnumConverter(),
                new IntegrityMethodConverter()
            }
        };

        this.jsonWriter = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = true,
        });
    }

    public void EndDocument()
    {
        jsonWriter.WriteEndArray();
        jsonWriter.WriteEndObject();
    }

    public void Serialize(Element obj, Type type)
    {
        System.Text.Json.JsonSerializer.Serialize(jsonWriter, obj, type, jsonOptions);
    }

    public void Start()
    {
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
