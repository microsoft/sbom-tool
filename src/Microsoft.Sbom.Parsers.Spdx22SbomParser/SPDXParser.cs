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
using System.Linq;
using System.Text.Json;

namespace Microsoft.Sbom;

/// <summary>
/// Parses a SPDX SBOM file.
/// </summary>
public class SPDXParser : ISbomParser
{
    private bool isFileArrayParsingStarted = false;
    private bool isFileArrayParsingFinished = false;

    private bool isPackageArrayParsingStarted = false;
    private bool isPackageArrayParsingFinished = false;

    private bool isRelationshipArrayParsingStarted = false;
    private bool isRelationshipArrayParsingFinished = false;

    private bool isExternalReferencesArrayParsingStarted = false;
    private bool isExternalReferencesArrayParsingFinished = false;

    private bool isParsingStarted = false;
    private bool stateChangedInPreviousOperation = true;

    private readonly Stream stream;

    private ParserState parserState = ParserState.NONE;
    private byte[] buffer;
    private JsonReaderState readerState;
    private bool isFinalBlock;

    // For unit tests only.
    private readonly bool ignoreValidation = false;

    public ParserState CurrentState
    {
        get 
        {
            return parserState; 
        }

        private set 
        {
            if (value == ParserState.FINISHED && !ignoreValidation)
            {
                ValidateParsingComplete();
            }

            parserState = value; 
        }
    }

    public SPDXParser(Stream stream)
        : this(stream, Constants.ReadBufferSize, false)
    {
    }

    // Used in unit tests
    internal SPDXParser(Stream stream, int bufferSize = Constants.ReadBufferSize, bool ignoreValidation = false)
    {
        buffer = new byte[bufferSize];
        readerState = default;
        isFinalBlock = false;
        stateChangedInPreviousOperation = false;
        this.ignoreValidation = ignoreValidation;
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

        // Validate buffer is not of 0 length.
        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
        }

        // Fill up the buffer.
        if (!stream.CanRead || stream.Read(buffer) == 0)
        {
            throw new EndOfStreamException();
        }
    }

    private readonly ManifestInfo spdxManifestInfo = new ManifestInfo
    {
        Name = Constants.SPDXName,
        Version = Constants.SPDXVersion
    };

    /// <inheritdoc/>
    public SBOMMetadata GetMetadata()
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public ParserState Next()
    {
        if (parserState == ParserState.FINISHED
            || (stateChangedInPreviousOperation && parserState != ParserState.INTERNAL_SKIP))
        {
            return parserState;
        }

        var nextState = stateChangedInPreviousOperation ? parserState : MoveToNextState();
        if (nextState == ParserState.INTERNAL_SKIP)
        {
            nextState = SkipInternalProperties();
        }

        stateChangedInPreviousOperation = false;
        CurrentState = nextState;
        return nextState;
        
        ParserState MoveToNextState()
        {
            try
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);

                if (!isParsingStarted)
                {
                    ParserUtils.SkipNoneTokens(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);

                    isParsingStarted = true;
                }

                var parser = new RootPropertiesParser(stream);
                var result = parser.MoveNext(ref buffer, ref reader);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
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

    private void ValidateParsingComplete()
    {
        var isPackageArrayProcessing = isPackageArrayParsingStarted && !isPackageArrayParsingFinished;
        var isFileArrayProcessing = isFileArrayParsingStarted && !isFileArrayParsingFinished;
        var isRelationshipArrayProcessing = isRelationshipArrayParsingStarted && !isRelationshipArrayParsingFinished;
        var isExternalRefArrayProcessing = isExternalReferencesArrayParsingStarted && !isExternalReferencesArrayParsingFinished;

        if (isFileArrayProcessing || isPackageArrayProcessing || isRelationshipArrayProcessing || isExternalRefArrayProcessing)
        {
            throw new ParserException($"Parser has reached the Finished state while we are still processing some properties.");
        }

        var missingProps = new List<string>();
        if (!isPackageArrayParsingStarted)
        {
            missingProps.Add("packages");
        }

        if (!isFileArrayParsingStarted)
        {
            missingProps.Add("files");
        }

        if (!isRelationshipArrayParsingStarted)
        {
            missingProps.Add("relationships");
        }

        if (missingProps.Any())
        {
            throw new ParserException($"The SPDX document is missing required properties: {string.Join(",", missingProps)}.");
        }
    }

    private ParserState SkipInternalProperties()
    {
        ParserState internalParserState;
        do
        {
            internalParserState = SkipPropertyInternal();
        }
        while (internalParserState == ParserState.INTERNAL_SKIP);

        return internalParserState;

        ParserState SkipPropertyInternal()
        {
            var reader = new Utf8JsonReader(buffer, isFinalBlock: isFinalBlock, readerState);
            ParserUtils.SkipProperty(stream, ref buffer, ref reader);

            var rootPropertiesParser = new RootPropertiesParser(stream);
            var parserState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
            ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);

            isFinalBlock = reader.IsFinalBlock;
            readerState = reader.CurrentState;
            return parserState;
        }
    }

    /// <inheritdoc/>
    public IEnumerable<SBOMReference> GetReferences()
    {
        if (parserState != ParserState.REFERENCES)
        {
            throw new ParserException($"The parser is not currently enumerating references. Current state: {CurrentState}");
        }

        while (GetExternalDocumentReferences(stream, out SpdxExternalDocumentReference spdxExternalDocumentReference) != 0)
        {
            yield return spdxExternalDocumentReference.ToSbomReference();
        }

        long GetExternalDocumentReferences(Stream stream, out SpdxExternalDocumentReference spdxExternalDocumentReference)
        {
            try
            {
                if (isExternalReferencesArrayParsingFinished)
                {
                    spdxExternalDocumentReference = null;
                    return 0;
                }

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
                    CurrentState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                    isExternalReferencesArrayParsingFinished = true;
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
    public IEnumerable<SBOMRelationship> GetRelationships()
    {
        if (parserState != ParserState.RELATIONSHIPS)
        {
            throw new ParserException($"The parser is not currently enumerating relationships. Current state: {CurrentState}");
        }

        while (GetPackages(stream, out SPDXRelationship sbomRelationship) != 0)
        {
            yield return sbomRelationship.ToSbomRelationship();
        }

        long GetPackages(Stream stream, out SPDXRelationship sbomRelationship)
        {
            try
            {
                if (isRelationshipArrayParsingFinished)
                {
                    sbomRelationship = null;
                    return 0;
                }

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
                    CurrentState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                    isRelationshipArrayParsingFinished = true;
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
    public IEnumerable<SBOMPackage> GetPackages()
    {
        if (parserState != ParserState.PACKAGES)
        {
            throw new ParserException($"The parser is not currently enumerating packages. Current state: {CurrentState}");
        }

        while (GetPackages(stream, out SPDXPackage sbomPackage) != 0)
        {
            yield return sbomPackage.ToSbomPackage();
        }

        long GetPackages(Stream stream, out SPDXPackage sbomPackage)
        {
            try
            {
                if (isPackageArrayParsingFinished)
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
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    var rootPropertiesParser = new RootPropertiesParser(stream);
                    CurrentState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                    isPackageArrayParsingFinished = true;
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
    public IEnumerable<SBOMFile> GetFiles()
    {
        if (parserState != ParserState.FILES)
        {
            throw new ParserException($"The parser is not currently enumerating files. Current state: {CurrentState}");
        }

        while (GetFiles(stream, out SPDXFile sbomFile) != 0)
        {
            yield return sbomFile.ToSbomFile();
        }

        long GetFiles(Stream stream, out SPDXFile sbomFile)
        {
            try
            {
                if (isFileArrayParsingFinished)
                {
                    sbomFile = null;
                    return 0;
                }

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
                    CurrentState = rootPropertiesParser.MoveNext(ref buffer, ref reader);
                    stateChangedInPreviousOperation = true;
                    isFileArrayParsingFinished = true;
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
