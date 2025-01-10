// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

public class ElementSerializer : JsonConverter<List<Element>>
{
    public override List<Element> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotImplementedException("Deserialization of Elements into specific subtypes is not implemented yet.");

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
