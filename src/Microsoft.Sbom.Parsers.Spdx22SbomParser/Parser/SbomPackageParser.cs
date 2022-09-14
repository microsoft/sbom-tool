// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Exceptions;
using System;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses a <see cref="SBOMPackage"/> object from a 'packages' array.
/// </summary>
internal ref struct SbomPackageParser
{
    private const string NameProperty = "name";

    private readonly Stream stream;
    private readonly SBOMPackage sbomPackage = new ();

    public SbomPackageParser(Stream stream)
    {
        this.stream = stream ?? throw new System.ArgumentNullException(nameof(stream));
    }

    internal long GetSbomPackage(ref byte[] buffer, ref Utf8JsonReader reader, out SBOMPackage sbomPackage)
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

    private void ValidateSbomFile(SBOMPackage sbomPackage)
    {
        throw new NotImplementedException();
    }

    private void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case NameProperty:
                 ParserUtils.Read(stream, ref buffer, ref reader);
                 sbomPackage.PackageName = ParserUtils.ParseNextString(stream, ref reader);
                 break;
        }
    }
}
