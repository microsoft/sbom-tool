using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses <see cref="SBOMFile"/> object from a 'files' array.
/// </summary>
internal ref struct SbomFileParser
{
    private byte[] buffer;
    private Stream stream;
    private JsonReaderState state;
    private SBOMFile sbomFile;

    public JsonReaderState CurrentState => state;

    public SbomFileParser(byte[] buffer, Stream stream, JsonReaderState state = default)
    {
        this.buffer = buffer ?? throw new ArgumentNullException(nameof(buffer));
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
        this.state = state;

        sbomFile = new ();
    }

    public long GetSbomFile(out SBOMFile sbomFile)
    {
        // Fill buffer if empty
        if (buffer.All(b => b == 0))
        {
            if (!stream.CanRead)
            {
                sbomFile = null;
                return 0;
            }

            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                sbomFile = null;
                return 0;
            }
        }

        var reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: state);

        try
        {
            while (reader.TokenType != JsonTokenType.EndObject)
            {
                while (reader.TokenType != JsonTokenType.PropertyName)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                }

                ParseProperty(ref reader);
                ParserUtils.Read(stream, ref buffer, ref reader);
            }

            ParserUtils.Read(stream, ref buffer, ref reader);
        }
        catch (JsonException e)
        {
            sbomFile = null;
            throw new ParserError($"Error while parsing JSON, addtional details: ${e.Message}");
        }

        state = reader.CurrentState;
        sbomFile = this.sbomFile;
        return reader.BytesConsumed;
    }

    private void ParseProperty(ref Utf8JsonReader reader)
    {
        switch (reader.GetString())
        {
            case "fileName":
                sbomFile.Path = ParseNextString(ref reader);
                break;

            case "SPDXID":
                sbomFile.SPDXId = ParseNextString(ref reader);
                break;

            case "checksums":
                sbomFile.Checksum = ParseChecksumsArray(ref reader);
                break;

            case "licenseConcluded":
                sbomFile.LicenseConcluded = ParseNextString(ref reader);
                break;

            case "copyrightText": 
                sbomFile.FileCopyrightText = ParseNextString(ref reader);
                break;

            case "licenseInfoInFiles":
                sbomFile.LicenseInfoInFiles = ParseLicenseInfoInFilesArray(ref reader);
                break;

            default:
                SkipProperty(ref reader);
                break;
        }
    }

    private List<string> ParseLicenseInfoInFilesArray(ref Utf8JsonReader reader)
    {
        var licenses = new List<string>();

        // Read the opening [ of the array
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            while (reader.TokenType != JsonTokenType.StartArray)
            {
                ParserUtils.Read(stream, ref buffer, ref reader);
            }

            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            licenses.Add(reader.GetString());
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        return licenses;
    }

    private IEnumerable<Checksum> ParseChecksumsArray(ref Utf8JsonReader reader)
    {
        var checksums = new List<Checksum>();

        // Read the opening [ of the array
        ParserUtils.Read(stream, ref buffer, ref reader);

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            checksums.Add(ParseChecksumObject(ref reader));
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                ParserUtils.Read(stream, ref buffer, ref reader);
            }
        }

        return checksums;
    }

    private Checksum ParseChecksumObject(ref Utf8JsonReader reader)
    {
        var checksum = new Checksum();

        // Read the opening { of the object
        ParserUtils.Read(stream, ref buffer, ref reader);

        while (reader.TokenType != JsonTokenType.EndObject)
        {
            while (reader.TokenType != JsonTokenType.PropertyName)
            {
                ParserUtils.Read(stream, ref buffer, ref reader);
            }

            switch (reader.GetString())
            {
                case "algorithm":
                    checksum.Algorithm = new AlgorithmName(ParseNextString(ref reader), null);
                    break;

                case "checksumValue":
                    checksum.ChecksumValue = ParseNextString(ref reader);
                    break;
                
                default:
                    SkipProperty(ref reader);
                    break;
            }

            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        return checksum;
    }

    private string ParseNextString(ref Utf8JsonReader reader)
    {
        while (reader.TokenType != JsonTokenType.String)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        return reader.GetString();
    }

    private void SkipProperty(ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.PropertyName)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        if (reader.TokenType == JsonTokenType.StartObject
            || reader.TokenType == JsonTokenType.StartArray)
        {
            int arrayCount = 0;
            int objectCount = 0;
            do
            {
                arrayCount = reader.TokenType switch
                {
                    JsonTokenType.StartArray => arrayCount + 1,
                    JsonTokenType.EndArray => arrayCount - 1,
                    _ => arrayCount,
                };

                objectCount = reader.TokenType switch
                {
                    JsonTokenType.StartObject => objectCount + 1,
                    JsonTokenType.EndObject => objectCount - 1,
                    _ => arrayCount,
                };

                ParserUtils.Read(stream, ref buffer, ref reader);

            } while (arrayCount + objectCount != 0);
        }
    }
}
