using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Converters;
internal class IdentifierConverter : JsonConverter<Element>
{
    public override Element? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, Element value, JsonSerializerOptions options)
    {
        if (value is Identifier)
        {
            writer.WriteStringValue(value.spdxId?.ToString());
        }
        else
        {
            System.Text.Json.JsonSerializer.Serialize(writer, value, options);
        }
    }
}
