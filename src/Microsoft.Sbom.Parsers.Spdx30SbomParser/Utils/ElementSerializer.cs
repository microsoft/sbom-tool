// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Common.Spdx30Entities;

public class ElementSerializer : JsonConverter<List<Element>>
{
    public override List<Element> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected a JSON array.");
        }

        var elements = new List<Element>();

        // Read the start of the array
        reader.Read();

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            // Create a JsonDocument for the current element
            using var jsonDocument = JsonDocument.ParseValue(ref reader);
            var jsonObject = jsonDocument.RootElement;

            // Determine the type of the element
            if (!jsonObject.TryGetProperty("type", out var typeProperty))
            {
                throw new JsonException("Missing 'type' property in JSON element.");
            }

            var typeValue = typeProperty.GetString();
            Element element;

            // Map the type to the corresponding subclass
            switch (typeValue)
            {
                case "software_File":
                    element = JsonSerializer.Deserialize<File>(jsonObject.GetRawText(), options);
                    break;

                case "software_Package":
                    element = JsonSerializer.Deserialize<Package>(jsonObject.GetRawText(), options);
                    break;

                case "ExternalMap":
                    element = JsonSerializer.Deserialize<ExternalMap>(jsonObject.GetRawText(), options);
                    break;

                case "Relationship":
                    element = JsonSerializer.Deserialize<Relationship>(jsonObject.GetRawText(), options);
                    break;

                default:
                    element = JsonSerializer.Deserialize<Element>(jsonObject.GetRawText(), options);
                    break;
            }

            elements.Add(element);

            // Move to the next element in the array
            reader.Read();
        }

        return elements;
    }

    public override void Write(Utf8JsonWriter writer, List<Element> elements, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var element in elements)
        {
            JsonSerializer.Serialize(writer, element, element.GetType(), options);
        }

        writer.WriteEndArray();
    }
}
