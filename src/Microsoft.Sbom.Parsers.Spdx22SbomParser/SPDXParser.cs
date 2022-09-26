// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Microsoft.Sbom;

/// <summary>
/// Parses a SPDX SBOM file.
/// </summary>
public class SPDXParser : ISbomParser
{
    private bool isFileArrayParsingStarted = false;
    private bool isPackageArrayParsingStarted = false;
    private bool isRelationshipArrayParsingStarted = false;
    private bool isExternalReferencesArrayParsingStarted = false;
    private bool isParsingStarted = false;

    private ParserState parserState = ParserState.NONE;
    private byte[] buffer;

    public ParserState CurrentState => parserState;

    // Used in unit tests
    public SPDXParser(int bufferSize = Constants.ReadBufferSize)
    {
        buffer = new byte[bufferSize];
    }

    private readonly ManifestInfo spdxManifestInfo = new ManifestInfo
    {
        Name = Constants.SPDXName,
        Version = Constants.SPDXVersion
    };

    /// <inheritdoc/>
    public SBOMMetadata GetMetadata(Stream stream)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public ParserState Next(Stream stream)
    {
        JsonReaderState readerState = default;
        stream.Read(buffer);
        var nextState = MoveToNextState(stream);

        if (nextState == ParserState.INTERNAL_SKIP)
        {
            while (nextState == ParserState.INTERNAL_SKIP)
            {
                SkipProperty(stream);
                nextState = MoveToNextState(stream);
            }
        }

        parserState = nextState;
        return nextState;
        
        ParserState MoveToNextState(Stream stream)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isParsingStarted)
                {
                    ParserUtils.SkipFirstObjectToken(stream, ref buffer, ref reader);
                    isParsingStarted = true;
                }

                if (buffer.AsSpan<byte>().StartsWith(System.Text.Encoding.UTF8.GetBytes(",")))
                {
                    buffer[0] = Encoding.UTF8.GetBytes("{")[0];
                    ParserUtils.SkipFirstObjectToken(stream, ref buffer, ref reader);
                }

                var parser = new RootPropertiesParser(stream);
                var result = parser.MoveNext(ref buffer, ref reader);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    // TODO read to the end
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                    result = ParserState.FINISHED;
                }

                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, addtional details: ${e.Message}", e);
            }
        }
        
        void SkipProperty(Stream stream)
        {
            var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);
            ParserUtils.SkipProperty(stream, ref buffer, ref reader);
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMReference> GetReferences(Stream stream)
    {
        JsonReaderState readerState = default;

        stream.Read(buffer);

        while (GetExternalDocumentReferences(stream, out SpdxExternalDocumentReference spdxExternalDocumentReference) != 0)
        {
            yield return spdxExternalDocumentReference.ToSbomReference();
        }

        long GetExternalDocumentReferences(Stream stream, out SpdxExternalDocumentReference spdxExternalDocumentReference)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isExternalReferencesArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isExternalReferencesArrayParsingStarted = true;
                }

                var parser = new SbomExternalDocumentReferenceParser(stream);
                var result = parser.GetSbomExternalDocumentReference(ref buffer, ref reader, out spdxExternalDocumentReference);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, addtional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMRelationship> GetRelationships(Stream stream)
    {
        JsonReaderState readerState = default;

        stream.Read(buffer);

        while (GetPackages(stream, out SPDXRelationship sbomRelationship) != 0)
        {
            yield return sbomRelationship.ToSbomRelationship();
        }

        long GetPackages(Stream stream, out SPDXRelationship sbomRelationship)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isRelationshipArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isRelationshipArrayParsingStarted = true;
                }

                var parser = new SbomRelationshipParser(stream);
                var result = parser.GetSbomRelationship(ref buffer, ref reader, out sbomRelationship);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, addtional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMPackage> GetPackages(Stream stream)
    {
        JsonReaderState readerState = default;

        stream.Read(buffer);
        
        while (GetPackages(stream, out SPDXPackage sbomPackage) != 0)
        {
            yield return sbomPackage.ToSbomPackage();
        }

        long GetPackages(Stream stream, out SPDXPackage sbomPackage)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isPackageArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isPackageArrayParsingStarted = true;
                }

                var parser = new SbomPackageParser(stream);
                var result = parser.GetSbomPackage(ref buffer, ref reader, out sbomPackage);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, addtional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMFile> GetFiles(Stream stream)
    {
        JsonReaderState readerState = default;

        stream.Read(buffer);

        while (GetFiles(stream, out SPDXFile sbomFile) != 0)
        {
            yield return sbomFile.ToSbomFile();
        }

        long GetFiles(Stream stream, out SPDXFile sbomFile)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isFileArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isFileArrayParsingStarted = true;
                }

                var parser = new SbomFileParser(stream);
                var result = parser.GetSbomFile(ref buffer, ref reader, out sbomFile);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, addtional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { spdxManifestInfo };
}
