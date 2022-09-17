using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

internal class TestParser2
{
    private bool isFileArrayParsingStarted = false;
    private bool isPackageArrayParsingStarted = false;
    private bool isRelationshipArrayParsingStarted = false;
    private JsonReaderState readerState;
    private byte[] buffer;

    public TestParser2(int bufferSize = Constants.ReadBufferSize)
    {
        buffer = new byte[bufferSize];
    }

    public IEnumerable<SpdxExternalDocumentReference> GetExternalDocumentReferences(Stream stream)
    {
        stream.Read(buffer);

        while (GetExternalDocumentReferences(stream, out SpdxExternalDocumentReference spdxExternalDocumentReference) != 0)
        {
            yield return spdxExternalDocumentReference;
        }

        long GetExternalDocumentReferences(Stream stream, out SpdxExternalDocumentReference spdxExternalDocumentReference)
        {
            var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

            if (!isRelationshipArrayParsingStarted)
            {
                ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                isRelationshipArrayParsingStarted = true;
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
    }

    public IEnumerable<SPDXRelationship> GetRelationships(Stream stream)
    {
        stream.Read(buffer);

        while (GetPackages(stream, out SPDXRelationship sbomRelationship) != 0)
        {
            yield return sbomRelationship;
        }

        long GetPackages(Stream stream, out SPDXRelationship sbomRelationship)
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
    }

    public IEnumerable<SPDXPackage> GetPackages(Stream stream)
    {
        stream.Read(buffer);

        while (GetPackages(stream, out SPDXPackage sbomPackage) != 0)
        {
            yield return sbomPackage;
        }

        long GetPackages(Stream stream, out SPDXPackage sbomPackage)
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
    }

    public IEnumerable<SPDXFile> GetFiles(Stream stream)
    {        
        stream.Read(buffer);

        while (GetFiles(stream, out SPDXFile sbomFile) != 0)
        {
            yield return sbomFile;
        }

        long GetFiles(Stream stream, out SPDXFile sbomFile)
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
    }
}
