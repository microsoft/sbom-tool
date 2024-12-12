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
                    JsonSerializer.Serialize(writer, element as AnyLicenseInfo, options);
                    break;
                case "ContentIdentifier":
                    JsonSerializer.Serialize(writer, element as ContentIdentifier, options);
                    break;
                case "CreationInfo":
                    JsonSerializer.Serialize(writer, element as CreationInfo, options);
                    break;
                case "ExternalIdentifier":
                    JsonSerializer.Serialize(writer, element as ExternalIdentifier, options);
                    break;
                case "software_File":
                    JsonSerializer.Serialize(writer, element as File, options);
                    break;
                case "software_Package":
                    JsonSerializer.Serialize(writer, element as Package, options);
                    break;
                case "PackageVerificationCode":
                    JsonSerializer.Serialize(writer, element as PackageVerificationCode, options);
                    break;
                case "Relationship":
                    JsonSerializer.Serialize(writer, element as Spdx30Relationship, options);
                    break;
                case "Tool":
                    JsonSerializer.Serialize(writer, element as Tool, options);
                    break;
                case "Organization":
                    JsonSerializer.Serialize(writer, element as Organization, options);
                    break;
                case "NamespaceMap":
                    JsonSerializer.Serialize(writer, element as NamespaceMap, options);
                    break;
                case "NoAssertionElement":
                    JsonSerializer.Serialize(writer, element as NoAssertionElement, options);
                    break;
                default:
                    JsonSerializer.Serialize(writer, element, options);
                    break;
            }
        }

        writer.WriteEndArray();
    }
}
