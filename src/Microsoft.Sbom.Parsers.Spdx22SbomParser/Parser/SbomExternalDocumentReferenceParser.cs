// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses <see cref="SpdxExternalDocumentReference"/> object from a 'files' array.
/// </summary>
internal ref struct SbomExternalDocumentReferenceParser
{
    private const string ExternalDocumentIdProperty = "externalDocumentId";
    private const string SpdxDocumentProperty = "spdxDocument";
    private const string ChecksumProperty = "checksum";

    private readonly Stream stream;
    private readonly SpdxExternalDocumentReference spdxExternalDocumentReference = new ();

    public SbomExternalDocumentReferenceParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal long GetSbomExternalDocumentReference(ref byte[] buffer, ref Utf8JsonReader reader, out SpdxExternalDocumentReference spdxExternalDocumentReference)
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
                spdxExternalDocumentReference = null;
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
            ValidateSbomExternalDocumentReference(this.spdxExternalDocumentReference);

            spdxExternalDocumentReference = this.spdxExternalDocumentReference;
            return reader.BytesConsumed;
        }
        catch (EndOfStreamException)
        {
            spdxExternalDocumentReference = null;
            return 0;
        }
        catch (JsonException e)
        {
            spdxExternalDocumentReference = null;
            throw new ParserException($"Error while parsing JSON, addtional details: ${e.Message}", e);
        }
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case ExternalDocumentIdProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                spdxExternalDocumentReference.ExternalDocumentId = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case SpdxDocumentProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                spdxExternalDocumentReference.SpdxDocument = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case ChecksumProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                spdxExternalDocumentReference.Checksum = ParserUtils.ParseChecksumObject(stream, ref reader, ref buffer);
                break;

            default:
                ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                break;
        }
    }

    private void ValidateSbomExternalDocumentReference(SpdxExternalDocumentReference spdxExternalDocumentReference)
    {
        var missingProps = new List<string>();

        if (string.IsNullOrWhiteSpace(spdxExternalDocumentReference.SpdxDocument))
        {
            missingProps.Add(nameof(spdxExternalDocumentReference.SpdxDocument));
        }

        if (string.IsNullOrWhiteSpace(spdxExternalDocumentReference.ExternalDocumentId))
        {
            missingProps.Add(nameof(spdxExternalDocumentReference.ExternalDocumentId));
        }


        if (spdxExternalDocumentReference.Checksum == null 
            || spdxExternalDocumentReference.Checksum.Algorithm != AlgorithmName.SHA1.Name)
        {
            missingProps.Add(nameof(spdxExternalDocumentReference.Checksum));
        }

        if (missingProps.Count() > 0)
        {
            throw new ParserException($"Missing required value(s) for file object at position {stream.Position}: {string.Join(",", missingProps)}");
        }
    }
}
