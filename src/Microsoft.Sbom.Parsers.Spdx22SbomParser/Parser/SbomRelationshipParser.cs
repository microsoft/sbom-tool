// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses a <see cref="SPDXRelationship"/> object from a 'packages' array.
/// </summary>
internal ref struct SbomRelationshipParser
{
    private const string SpdxElementIdProperty = "spdxElementId";
    private const string RelatedSpdxElementProperty = "relatedSpdxElement";
    private const string RelationshipTypeProperty = "relationshipType";

    private readonly Stream stream;
    private readonly SPDXRelationship sbomRelationship = new();

    public SbomRelationshipParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal long GetSbomRelationship(ref byte[] buffer, ref Utf8JsonReader reader, out SPDXRelationship sbomRelationship)
    {
        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
        }

        try
        {
            // If the end of the array is reached, return with null value to signal end of the array.
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                sbomRelationship = null;
                return 0;
            }

            // Read the start { of this object.
            ParserUtils.SkipNoneTokens(stream, ref buffer, ref reader);
            ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

            // Move to the first property name token.
            ParserUtils.Read(stream, ref buffer, ref reader);
            ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);

            while (reader.TokenType != JsonTokenType.EndObject)
            {
                ParseProperty(ref reader, ref buffer);

                // Read the end } of this object or the next property name.
                ParserUtils.Read(stream, ref buffer, ref reader);
            }

            // Validate the created object
            ValidateSbomRelationship(this.sbomRelationship);

            sbomRelationship = this.sbomRelationship;
            return reader.BytesConsumed;
        }
        catch (EndOfStreamException)
        {
            sbomRelationship = null;
            return 0;
        }
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case SpdxElementIdProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomRelationship.SourceElementId = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case RelatedSpdxElementProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomRelationship.TargetElementId = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case RelationshipTypeProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                var relationshipTypeStr = ParserUtils.ParseNextString(stream, ref reader);
                if (Enum.TryParse(relationshipTypeStr, true, out SPDXRelationshipType relationshipType))
                {
                    sbomRelationship.RelationshipType = relationshipType;
                }
                else
                {
                    throw new ParserException($"Illegal value '{relationshipType}' found for 'relationshipType' at stream position {stream.Position}");
                }

                break;

            default:
                ParserUtils.Read(stream, ref buffer, ref reader);
                ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                break;
        }
    }

    private void ValidateSbomRelationship(SPDXRelationship sbomRelationship)
    {
        var missingProps = new List<string>();

        if (string.IsNullOrWhiteSpace(sbomRelationship.TargetElementId))
        {
            missingProps.Add(nameof(sbomRelationship.TargetElementId));
        }

        if (string.IsNullOrWhiteSpace(sbomRelationship.SourceElementId))
        {
            missingProps.Add(nameof(sbomRelationship.SourceElementId));
        }

        if (missingProps.Any())
        {
            throw new ParserException($"Missing required value(s) for relationship object at position {stream.Position}: {string.Join(",", missingProps)}");
        }
    }
}
