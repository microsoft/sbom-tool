// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using System;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses the root properties of a SBOM and returns the related <see cref="ParserState"/>.
/// </summary>
internal ref struct RootPropertiesParser
{
    private const string FilesProperty = "files";
    private const string PackagesProperty = "packages";
    private const string RelationshipsProperty = "relationships";
    private const string ExternalDocumentRefsProperty = "externalDocumentRefs";
    private readonly Stream stream;

    public RootPropertiesParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal ParserState MoveNext(ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
        }

        try
        {
            // Read the next token.
            ParserUtils.Read(stream, ref buffer, ref reader);

            // If the end of the Json Object is reached, return parser Finished state.
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return ParserState.FINISHED;
            }

            ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);
            return ParseNextPropertyAsParserState(ref reader, ref buffer);
        }
        catch (EndOfStreamException)
        {
            return ParserState.FINISHED;
        }
        catch (JsonException e)
        {
            throw new ParserException($"Error while parsing JSON, additional details: ${e.Message}", e);
        }
    }

    private ParserState ParseNextPropertyAsParserState(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var nextState = reader.GetString() switch
        {
            FilesProperty => ParserState.FILES,
            PackagesProperty => ParserState.PACKAGES,
            RelationshipsProperty => ParserState.RELATIONSHIPS,
            ExternalDocumentRefsProperty => ParserState.REFERENCES,
            _ => ParserState.INTERNAL_SKIP,
        };

        // Consume the PropertyName token.
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
        return nextState;
    }
}