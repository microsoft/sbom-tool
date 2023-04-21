// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses <see cref="SPDXFile"/> object from a 'files' array.
/// </summary>
internal ref struct SbomFileParser
{
    // Internal properties.
    private const string LicenseInfoInFilesProperty = "licenseInfoInFiles";
    private const string FileNameProperty = "fileName";
    private const string SPDXIdProperty = "SPDXID";
    private const string ChecksumsProperty = "checksums";
    private const string LicenseConcludedProperty = "licenseConcluded";
    private const string CopyrightTextProperty = "copyrightText";

    private readonly Stream stream;
    private readonly SPDXFile sbomFile = new ();

    public SbomFileParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    /// <summary>
    /// Parses the SPDX SBOM 'files' array section and generates a <see cref="SBOMFile"/> object for it.
    /// 
    /// If an object is parsed successfully, the <see cref="sbomFile"/> parameter will have the newly created
    /// object.
    /// </summary>
    /// <param name="buffer">The buffer where the stream will be read.</param>
    /// <param name="reader">The UTF8 reader used to parse the JSON.</param>
    /// <param name="sbomFile">The object that eventually will be assigned.</param>
    /// <returns>The total number of bytes read consumed from the stream to parse the object.
    /// This value will be 0 if the parsing fails or the end of the stream has been reached.
    /// </returns>
    /// <exception cref="ParserException"></exception>
    public long GetSbomFile(ref byte[] buffer, ref Utf8JsonReader reader, out SPDXFile sbomFile)
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
    }

    private void ValidateSbomFile(SPDXFile sbomFile)
    {
        // I want to use the DataAnnotations Validator here, but will check with CB first
        // before adding a new dependency.
        var missingProps = new List<string>();
       
        if (sbomFile.FileChecksums == null || sbomFile.FileChecksums.Where(c => c.Algorithm == AlgorithmName.SHA256.Name).Count() == 0)
        {
            missingProps.Add(nameof(sbomFile.FileChecksums));
        }

        if (string.IsNullOrEmpty(sbomFile.FileName))
        {
            missingProps.Add(nameof(sbomFile.FileName));
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
            throw new ParserException($"Missing required value(s) for file object at position {stream.Position}: {string.Join(",", missingProps)}");
        }
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case FileNameProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.FileName = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case SPDXIdProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.SPDXId = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case ChecksumsProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.FileChecksums = ParseChecksumsArray(ref reader, ref buffer);
                break;

            case LicenseConcludedProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.LicenseConcluded = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case CopyrightTextProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.FileCopyrightText = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case LicenseInfoInFilesProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomFile.LicenseInfoInFiles = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                break;

            default:
                ParserUtils.Read(stream, ref buffer, ref reader);
                ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                break;
        }
    }

    private List<Checksum> ParseChecksumsArray(ref Utf8JsonReader reader, ref byte[] buffer)
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

            checksums.Add(ParserUtils.ParseChecksumObject(stream, ref reader, ref buffer));
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndArray);

        return checksums;
    }
}
