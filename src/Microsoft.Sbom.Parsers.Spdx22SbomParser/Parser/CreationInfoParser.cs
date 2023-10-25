// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Exceptions;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Parses a <see cref="MetadataCreationInfo"/> object from a 'creationInfo' object.
/// </summary>
internal readonly ref struct CreationInfoParser
{
    private readonly Stream stream;
    private readonly MetadataCreationInfo creationInfo = new();

    public CreationInfoParser(Stream stream)
    {
        this.stream = stream;
    }

    internal MetadataCreationInfo GetCreationInfo(ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
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
        ValidateCreationInfo();

        return this.creationInfo;
    }

    private readonly void ValidateCreationInfo()
    {
        var missingProps = new List<string>();

        if (this.creationInfo.Created == default)
        {
            missingProps.Add(nameof(this.creationInfo.Created));
        }

        if (this.creationInfo.Creators == null || !this.creationInfo.Creators.Any())
        {
            missingProps.Add(nameof(this.creationInfo.Creators));
        }

        if (missingProps.Any())
        {
            throw new ParserException($"Missing required value(s) for creationInfo object at position {stream.Position}: {string.Join(",", missingProps)}");
        }
    }

    private readonly void ParseProperty(ref Utf8JsonReader reader, ref byte[] buffer)
    {
        switch (reader.GetString())
        {
            case "created":
                ParserUtils.Read(stream, ref buffer, ref reader);
                var createdString = ParserUtils.ParseNextString(stream, ref reader);
                this.creationInfo.Created = DateTime.Parse(createdString);
                break;

            case "creators":
                ParserUtils.Read(stream, ref buffer, ref reader);
                this.creationInfo.Creators = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                break;

            default:
                ParserUtils.Read(stream, ref buffer, ref reader);
                ParserUtils.SkipProperty(stream, ref buffer, ref reader);
                break;
        }
    }
}
