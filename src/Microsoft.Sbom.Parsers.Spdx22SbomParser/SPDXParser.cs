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

    private bool stateChangedInPreviousOperation = true;

    private ParserState parserState = ParserState.NONE;
    private byte[] buffer;

    private JsonReaderState readerState;
    private bool isFinalBlock;

    public ParserState CurrentState => parserState;

    // Used in unit tests
    public SPDXParser(int bufferSize = Constants.ReadBufferSize)
    {
        buffer = new byte[bufferSize];
        readerState = default;
        isFinalBlock = false;
        stateChangedInPreviousOperation = false;
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
        ParserState nextState;
        if (stateChangedInPreviousOperation)
        {
            if (CurrentState != ParserState.INTERNAL_SKIP)
            {
                return CurrentState;
            }

            stateChangedInPreviousOperation = false;
            nextState = CurrentState;
        }
        else
        {
            nextState = MoveToNextState(stream);
        }

        if (CurrentState == ParserState.FINISHED)
        {
            return CurrentState;
        }

        if (nextState == ParserState.INTERNAL_SKIP)
        {
            SkipProperty(stream);
            return CurrentState;
        }

        parserState = nextState;
        return nextState;
        
        ParserState MoveToNextState(Stream stream)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

                if (!isParsingStarted)
                {
                    ParserUtils.SkipFirstObjectToken(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader, true);

                    isParsingStarted = true;
                }

                // Since we don't preserve the state between the parsing (files, packages, etc),
                // we need to trick the parser into thinking that we are parsing a new object in case
                // we are scanning the next property (this will be true if the next token is a comma).
                if (buffer.AsSpan().StartsWith(Encoding.UTF8.GetBytes(",")))
                {
                    buffer[0] = Constants.StartObjectToken;
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

                isFinalBlock = reader.IsFinalBlock;
                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, additional details: ${e.Message}", e);
            }
        }
    }

    private void SkipProperty(Stream stream)
    {
        while (parserState == ParserState.INTERNAL_SKIP)
        {
            SkipPropertyInternal(stream);
        }

        stateChangedInPreviousOperation = true;
        return;

        void SkipPropertyInternal(Stream stream)
        {
            var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);
            //ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader, true);
            ParserUtils.SkipProperty(stream, ref buffer, ref reader);

            var rootPropertiesParser = new RootPropertiesParser(stream);
            parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
            ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader, true);

            isFinalBlock = reader.IsFinalBlock;
            readerState = reader.CurrentState;
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMReference> GetReferences(Stream stream)
    {
        while (GetExternalDocumentReferences(stream, out SpdxExternalDocumentReference spdxExternalDocumentReference) != 0)
        {
            yield return spdxExternalDocumentReference.ToSbomReference();
        }

        long GetExternalDocumentReferences(Stream stream, out SpdxExternalDocumentReference spdxExternalDocumentReference)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

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

                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    var rootPropertiesParser = new RootPropertiesParser(stream);
                    parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                }

                isFinalBlock = reader.IsFinalBlock;
                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, additional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMRelationship> GetRelationships(Stream stream)
    {
        while (GetPackages(stream, out SPDXRelationship sbomRelationship) != 0)
        {
            yield return sbomRelationship.ToSbomRelationship();
        }

        long GetPackages(Stream stream, out SPDXRelationship sbomRelationship)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

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

                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    var rootPropertiesParser = new RootPropertiesParser(stream);
                    parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                }
                isFinalBlock = reader.IsFinalBlock;
                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, additional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMPackage> GetPackages(Stream stream)
    {
        while (GetPackages(stream, out SPDXPackage sbomPackage) != 0)
        {
            yield return sbomPackage.ToSbomPackage();
        }

        long GetPackages(Stream stream, out SPDXPackage sbomPackage)
        {
            try
            {
                if (parserState != ParserState.PACKAGES)
                {
                    sbomPackage = null;
                    return 0;
                }

                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

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
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader, true);
                }

                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    var rootPropertiesParser = new RootPropertiesParser(stream);
                    parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                }

                isFinalBlock = reader.IsFinalBlock;
                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, additional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMFile> GetFiles(Stream stream)
    {
        while (GetFiles(stream, out SPDXFile sbomFile) != 0)
        {
            yield return sbomFile.ToSbomFile();
        }

        long GetFiles(Stream stream, out SPDXFile sbomFile)
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

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

                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    var rootPropertiesParser = new RootPropertiesParser(stream);
                    parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                }

                isFinalBlock = reader.IsFinalBlock;
                readerState = reader.CurrentState;
                return result;
            }
            catch (JsonException e)
            {
                throw new ParserException($"Error while parsing JSON at position {stream.Position}, additional details: ${e.Message}", e);
            }
        }
    }

    /// <inheritdoc/>
    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { spdxManifestInfo };
}
