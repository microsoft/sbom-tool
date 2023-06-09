using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Converters;
internal class IdentifierConverter : JsonConverter<List<Element>>
{
    public override List<Element>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, List<Element> value, JsonSerializerOptions options)
    {     
        writer.WriteStartArray();

        foreach (var item in value)
        {
            writer.WriteStringValue(item?.spdxId?.AbsoluteUri);
        }

        writer.WriteEndArray();
        //if (value.Any(element => element is Identifier))
        //{
        //    writer.WriteStartArray();

        //    foreach (var item in value)
        //    {
        //        writer.WriteStringValue(item?.spdxId?.AbsoluteUri);
        //    }

        //    writer.WriteEndArray();
        //}
        //else
        //{
        //    JsonSerializer.Serialize(writer, value, options);
        //}

    }
}
