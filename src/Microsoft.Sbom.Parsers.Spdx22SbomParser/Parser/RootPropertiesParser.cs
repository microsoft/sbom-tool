// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text.Json;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Utils;

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
    private const string SpdxVersionProperty = "spdxVersion";
    private const string DataLicenseProperty = "dataLicense";
    private const string SpdxIdProperty = "SPDXID";
    private const string NameProperty = "name";
    private const string DocumentNamespaceProperty = "documentNamespace";
    private const string CreationInfoProperty = "creationInfo";
    private const string DocumentDescribesProperty = "documentDescribes";

    private readonly Stream stream;

    public RootPropertiesParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal ParserStateResult MoveNext(ref byte[] buffer, ref Utf8JsonReader reader)
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
                return new ParserStateResult(ParserState.METADATA);
            }

            ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);
            return ParseNextPropertyAsParserState(ref reader, ref buffer);
        }
        catch (EndOfStreamException)
        {
            return new ParserStateResult(ParserState.FINISHED);
        }
        catch (JsonException e)
        {
            throw new ParserException($"Error while parsing JSON, additional details: ${e.Message}", e);
        }
    }

    private ParserStateResult ParseNextPropertyAsParserState(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var propertyName = reader.GetString();
        var nextState = propertyName switch
        {
            FilesProperty => ParserState.FILES,
            PackagesProperty => ParserState.PACKAGES,
            RelationshipsProperty => ParserState.RELATIONSHIPS,
            ExternalDocumentRefsProperty => ParserState.REFERENCES,
            SpdxVersionProperty => ParserState.INTERNAL_METADATA,
            DataLicenseProperty => ParserState.INTERNAL_METADATA,
            SpdxIdProperty => ParserState.INTERNAL_METADATA,
            NameProperty => ParserState.INTERNAL_METADATA,
            DocumentNamespaceProperty => ParserState.INTERNAL_METADATA,
            CreationInfoProperty => ParserState.INTERNAL_METADATA,
            DocumentDescribesProperty => ParserState.INTERNAL_METADATA,
            _ => ParserState.INTERNAL_SKIP,
        };

        // Consume the PropertyName token.
        ParserUtils.Read(stream, ref buffer, ref reader);
        var nextToken = string.Empty;
        
        // Capture the next token if the reader has already consumed it.
        if (reader.TokenStartIndex < reader.BytesConsumed) 
        {
            nextToken = ParserUtils.GetNextTokenString(ref reader);
        }

        ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
        return new ParserStateResult(nextState, propertyName, nextToken);
    }
}