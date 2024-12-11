// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

public class ElementSerializer : JsonConverter<List<Element>>
{
    public override List<Element> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException("Deserialization of Elements into specific subtypes is not implemented yet.");
    }

    public override void Write(Utf8JsonWriter writer, List<Element> elements, JsonSerializerOptions options)
    {
        writer.WriteStartArray();

        foreach (var element in elements)
        {
            switch (element.Type)
            {
                case "AnyLicenseInfo":
                    JsonSerializer.Serialize(writer, (AnyLicenseInfo)element, options);
                    break;
                case "ContentIdentifier":
                    JsonSerializer.Serialize(writer, (ContentIdentifier)element, options);
                    break;
                case "CreationInfo":
                    JsonSerializer.Serialize(writer, (CreationInfo)element, options);
                    break;
                case "ExternalIdentifier":
                    JsonSerializer.Serialize(writer, (ExternalIdentifier)element, options);
                    break;
                case "software_File":
                    JsonSerializer.Serialize(writer, (File)element, options);
                    break;
                case "software_Package":
                    JsonSerializer.Serialize(writer, (Package)element, options);
                    break;
                case "PackageVerificationCode":
                    JsonSerializer.Serialize(writer, (PackageVerificationCode)element, options);
                    break;
                case "Relationship":
                    JsonSerializer.Serialize(writer, (Spdx30Relationship)element, options);
                    break;
                case "Tool":
                    JsonSerializer.Serialize(writer, (Tool)element, options);
                    break;
                case "Organization":
                    JsonSerializer.Serialize(writer, (Organization)element, options);
                    break;
                case "NamespaceMap":
                    JsonSerializer.Serialize(writer, (NamespaceMap)element, options);
                    break;
                case "NoAssertionElement":
                    JsonSerializer.Serialize(writer, (NoAssertionElement)element, options);
                    break;
                default:
                    JsonSerializer.Serialize(writer, element, options);
                    break;
            }
        }

        writer.WriteEndArray();
    }
}
