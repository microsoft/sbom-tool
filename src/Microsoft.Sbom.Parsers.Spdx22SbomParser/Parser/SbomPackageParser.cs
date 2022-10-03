// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    private const string PackageVerificationCodeProperty = "packageVerificationCode";
    private const string PackageVerificationCodeValueProperty = "packageVerificationCodeValue";
    private const string PackageVerificationCodeExcludedFilesProperty = "packageVerificationCodeExcludedFiles";
    private const string LicenseInfoFromFilesProperty = "licenseInfoFromFiles";
    private const string HasFilesProperty = "hasFiles";
    private const string ExternalRefsProperty = "externalRefs";
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
            ValidateSbomPackage(this.sbomPackage);

            sbomPackage = this.sbomPackage;
            return reader.BytesConsumed;
        }
        catch (EndOfStreamException)
        {
            sbomPackage = null;
            return 0;
        }
    }

    private void ValidateSbomPackage(SPDXPackage sbomPackage)
    {
        var missingProps = new List<string>();

        if (string.IsNullOrWhiteSpace(sbomPackage.Name))
        {
            missingProps.Add(nameof(sbomPackage.Name));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.SpdxId))
        {
            missingProps.Add(nameof(sbomPackage.SpdxId));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.DownloadLocation))
        {
            missingProps.Add(nameof(sbomPackage.DownloadLocation));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.LicenseConcluded))
        {
            missingProps.Add(nameof(sbomPackage.LicenseConcluded));
        }

        if (sbomPackage.LicenseInfoFromFiles == null || sbomPackage.LicenseInfoFromFiles.Count == 0)
        {
            missingProps.Add(nameof(sbomPackage.LicenseInfoFromFiles));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.LicenseDeclared))
        {
            missingProps.Add(nameof(sbomPackage.LicenseDeclared));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.CopyrightText))
        {
            missingProps.Add(nameof(sbomPackage.CopyrightText));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.VersionInfo))
        {
            missingProps.Add(nameof(sbomPackage.VersionInfo));
        }

        if (string.IsNullOrWhiteSpace(sbomPackage.Supplier))
        {
            missingProps.Add(nameof(sbomPackage.Supplier));
        }

        if (sbomPackage.PackageVerificationCode != null 
            && string.IsNullOrWhiteSpace(sbomPackage.PackageVerificationCode.PackageVerificationCodeValue))
        {
            missingProps.Add(nameof(sbomPackage.PackageVerificationCode));
        }

        if (sbomPackage.ExternalReferences != null)
        {
            foreach (var reference in sbomPackage.ExternalReferences)
            {
                if (string.IsNullOrWhiteSpace(reference.ReferenceCategory)
                    || string.IsNullOrWhiteSpace(reference.Locator))
                {
                    missingProps.Add(nameof(sbomPackage.ExternalReferences));
                }
            }
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
                sbomPackage.CopyrightText = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case VersionInfoProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.VersionInfo = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case SupplierProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.Supplier = ParserUtils.ParseNextString(stream, ref reader);
                break;

            case PackageVerificationCodeProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.PackageVerificationCode = ParsePackageVerificationCodeObject(ref buffer, ref reader);
                break;

            case LicenseInfoFromFilesProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.LicenseInfoFromFiles = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                break;

            case HasFilesProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.HasFiles = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                break;

            case ExternalRefsProperty:
                ParserUtils.Read(stream, ref buffer, ref reader);
                sbomPackage.ExternalReferences = ParseExternalReferences(ref reader, ref buffer);
                break;

            default:
                ParserUtils.Read(stream, ref buffer, ref reader);
                ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                break;
        }
    }

    private IList<ExternalReference> ParseExternalReferences(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var references = new List<ExternalReference>();

        // Read the opening [ of the array
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartArray);

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            references.Add(ParseExternalReference(ref reader, ref buffer));
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndArray);

        return references;
    }

    private ExternalReference ParseExternalReference(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        ExternalReference reference = new ();

        // Read the opening { of the object
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

        // Move to the first property token
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);

        while (reader.TokenType != JsonTokenType.EndObject)
        {
            switch (reader.GetString())
            {
                case "referenceCategory":
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    reference.ReferenceCategory = ParserUtils.ParseNextString(stream, ref reader);
                    break;

                case "referenceLocator":
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    reference.Locator = ParserUtils.ParseNextString(stream, ref reader);
                    break;

                case "referenceType":
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    var referenceType = ParserUtils.ParseNextString(stream, ref reader);
                    if (Enum.TryParse(referenceType, true, out ExternalRepositoryType externalRepositoryType))
                    {
                        reference.Type = externalRepositoryType;
                    }
                    else
                    {
                        throw new ParserException($"Illegal value '{referenceType}' found for 'referenceType' at stream position {stream.Position}");
                    }

                    break;

                default:
                    ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                    break;
            }

            // Read the end } of this object or the next property name.
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndObject);

        return reference;
    }

    private PackageVerificationCode ParsePackageVerificationCodeObject(ref byte[] buffer, ref Utf8JsonReader reader)
    {
        PackageVerificationCode packageVerificationCode = new ();

        // Read the opening { of the object
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

        // Move to the first property token
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);

        while (reader.TokenType != JsonTokenType.EndObject)
        {
            switch (reader.GetString())
            {
                case PackageVerificationCodeValueProperty:
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    packageVerificationCode.PackageVerificationCodeValue = ParserUtils.ParseNextString(stream, ref reader);
                    break;

                case PackageVerificationCodeExcludedFilesProperty:
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    packageVerificationCode.PackageVerificationCodeExcludedFiles = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                    break;

                default:
                    ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                    break;
            }

            // Read the end } of this object or the next property name.
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        ParserUtils.AssertTokenType(stream, ref reader, JsonTokenType.EndObject);

        return packageVerificationCode;
    }
}
