// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
    private readonly Stream stream;
    private readonly SBOMFile sbomFile;

    public SbomFileParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

        sbomFile = new ();
    }

    /// <summary>
    /// Returns an iterator of <see cref="SBOMFile"/> objects by parsing the SPDX JSON files section.
    /// </summary>
    /// <param name="buffer">The buffer where the stream will be read.</param>
    /// <param name="reader">The UTF8 reader used to parse the JSON.</param>
    /// <param name="sbomFile">The object that eventually will be assigned.</param>
    /// <returns></returns>
    /// <exception cref="ParserError"></exception>
    public long GetSbomFile(ref byte[] buffer, ref Utf8JsonReader reader, out SBOMFile sbomFile)
    {
        try
        {
            // If the end of the array is reached, return with null value to signal end of the array.
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                sbomFile = null;
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
            ValidateSbomFile(this.sbomFile);

            sbomFile = this.sbomFile;
            return reader.BytesConsumed;
        }
        catch (EndOfStreamException)
        {
            sbomFile = null;
            return 0;
        }
        catch (JsonException e)
        {
            sbomFile = null;
            throw new ParserError($"Error while parsing JSON, addtional details: ${e.Message}");
        }
    }

    private void ValidateSbomFile(SBOMFile sbomFile)
    {
        // I want to use the DataAnnotations Validator here, but will check with CB first
        // before adding a new dependency.
        var missingProps = new List<string>();

        if (sbomFile.Checksum == null || sbomFile.Checksum.Where(c => c.Algorithm.Name == "SHA256").Count() == 0)
        {
            missingProps.Add(nameof(sbomFile.Checksum));
        }

        if (string.IsNullOrEmpty(sbomFile.Path))
        {
            missingProps.Add(nameof(sbomFile.Path));
        }

        if (string.IsNullOrEmpty(sbomFile.SPDXId))
        {
            missingProps.Add(nameof(sbomFile.SPDXId));
        }

        if (string.IsNullOrEmpty(sbomFile.FileCopyrightText))
        {
            missingProps.Add(nameof(sbomFile.FileCopyrightText));
        }

        if (string.IsNullOrEmpty(sbomFile.LicenseConcluded))
        {
            missingProps.Add(nameof(sbomFile.LicenseConcluded));
        }

        if (sbomFile.LicenseInfoInFiles == null || sbomFile.LicenseInfoInFiles.Count == 0)
        {
            missingProps.Add(nameof(sbomFile.LicenseInfoInFiles));
        }

        if (missingProps.Count() > 0)
        {
            throw new ParserError($"Missing required value(s) for file object at position {stream.Position}: {string.Join(",", missingProps)}");
        }
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case "fileName":
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.Path = ParseNextString(ref reader, ref buffer);
                break;

            case "SPDXID":
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.SPDXId = ParseNextString(ref reader, ref buffer);
                break;

            case "checksums":
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.Checksum = ParseChecksumsArray(ref reader, ref buffer);
                break;

            case "licenseConcluded":
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.LicenseConcluded = ParseNextString(ref reader, ref buffer);
                break;

            case "copyrightText": 
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.FileCopyrightText = ParseNextString(ref reader, ref buffer);
                break;

            case "licenseInfoInFiles":
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.LicenseInfoInFiles = ParseLicenseInfoInFilesArray(ref reader, ref buffer);
                break;

            default:
                SkipProperty(ref reader, ref buffer);
                break;
        }
    }

    private List<string> ParseLicenseInfoInFilesArray(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var licenses = new List<string>();

        // Read the opening [ of the array
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartArray);

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            licenses.Add(reader.GetString());
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndArray);
        return licenses;
    }

    private IEnumerable<Checksum> ParseChecksumsArray(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var checksums = new List<Checksum>();

        // Read the opening [ of the array
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartArray);

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            checksums.Add(ParseChecksumObject(ref reader, ref buffer));
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndArray);

        return checksums;
    }

    private Checksum ParseChecksumObject(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var checksum = new Checksum();

        // Read the opening { of the object
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

        // Move to the first property token
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);

        while (reader.TokenType != JsonTokenType.EndObject)
        {
            switch (reader.GetString())
            {
                case "algorithm":
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    checksum.Algorithm = new AlgorithmName(ParseNextString(ref reader, ref buffer), null);
                    break;

                case "checksumValue":
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    checksum.ChecksumValue = ParseNextString(ref reader, ref buffer);
                    break;
                
                default:
                    SkipProperty(ref reader, ref buffer);
                    break;
            }

            // Read the end } of this object or the next property name.
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndObject);

        return checksum;
    }

    private string ParseNextString(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.String);
        return reader.GetString();
    }

    private void SkipProperty(ref Utf8JsonReader reader, ref byte[] buffer)
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
            while (true)
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
                    _ => objectCount,
                };

                if (arrayCount + objectCount != 0)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                }
                else
                {
                    break;
                }
            }
        }
    }
}
