// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses a <see cref="SPDXPackage"/> object from a 'packages' array.
/// </summary>
internal ref struct SbomPackageParser
{
    private const string NameProperty = "name";
    private const string SPDXIDProperty = "SPDXID";
    private const string DownloadLocationProperty = "downloadLocation";
    private const string FilesAnalyzedProperty = "filesAnalyzed";
    private const string LicenseConcludedProperty = "licenseConcluded";
    private const string LicenseDeclaredProperty = "licenseDeclared";
    private const string CopyrightTextProperty = "copyrightText";
    private const string VersionInfoProperty = "versionInfo";
    private const string SupplierProperty = "supplier";

    private readonly Stream stream;
    private readonly SPDXPackage sbomPackage = new ();

    public SbomPackageParser(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal long GetSbomPackage(ref byte[] buffer, ref Utf8JsonReader reader, out SPDXPackage sbomPackage)
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
                sbomPackage = null;
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
            ValidateSbomFile(this.sbomPackage);

            sbomPackage = this.sbomPackage;
            return reader.BytesConsumed;
        }
        catch (EndOfStreamException)
        {
            sbomPackage = null;
            return 0;
        }
        catch (JsonException e)
        {
            sbomPackage = null;
            throw new ParserException($"Error while parsing JSON, addtional details: ${e.Message}", e);
        }
    }

    private void ValidateSbomFile(SPDXPackage sbomPackage)
    {
        //throw new NotImplementedException();
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case NameProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.Name = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case SPDXIDProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.SpdxId = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case DownloadLocationProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.DownloadLocation = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case FilesAnalyzedProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.FilesAnalyzed = ParserUtils.ParseNextBoolean(stream, ref reader);
                break;

            case LicenseConcludedProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseConcluded = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case LicenseDeclaredProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseDeclared = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case CopyrightTextProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseDeclared = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case VersionInfoProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseDeclared = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case SupplierProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseDeclared = ParserUtils.ParseNextString(stream, ref reader);
                break;

            default:
                ParserUtils.SkipProperty(stream, ref reader, ref buffer);
                break;
        }
    }
}
