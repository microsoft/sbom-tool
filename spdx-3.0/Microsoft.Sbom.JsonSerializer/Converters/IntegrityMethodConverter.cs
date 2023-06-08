using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Converters;
internal class IntegrityMethodConverter : JsonConverter<IntegrityMethod>
{
    public override IntegrityMethod? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, IntegrityMethod value, JsonSerializerOptions options)
    {
        if (value is Hash hash)
        {
            System.Text.Json.JsonSerializer.Serialize(writer, hash, options);
        }
    }
}
