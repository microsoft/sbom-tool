﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Text.Json;
using System.Text;
using System;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Exceptions;

namespace Microsoft.Sbom.Parser;

internal class ParserUtils
{
    public static void Read(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        // If the buffer is empty, refill the buffer.
        if (buffer[0] == 0)
        {
            if (!stream.CanRead || stream.Read(buffer) == 0)
            {
                throw new EndOfStreamException();
            }
        }

        while (!reader.Read())
        {
            // Not enough of the JSON is in the buffer to complete a read.
            GetMoreBytesFromStream(stream, ref buffer, ref reader);
        }
    }

    internal static void AssertTokenType(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader, JsonTokenType expectedTokenType)
    {
        if (reader.TokenType != expectedTokenType)
        {
            throw new ParserError($"Expected a '{Constants.JsonTokenStrings[(byte)expectedTokenType]}' at position {stream.Position}");
        }
    }

    internal static void SkipNoneTokens(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        while (reader.TokenType == JsonTokenType.None)
        {
            Read(stream, ref buffer, ref reader);
        }
    }

    internal static string GetStringValue(ReadOnlySpan<byte> valueSpan)
    {
        return Encoding.UTF8.GetString(valueSpan.ToArray());
    }

    public static void GetMoreBytesFromStream(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        int bytesRead;
        if (reader.BytesConsumed < buffer.Length)
        {
            ReadOnlySpan<byte> leftover = buffer.AsSpan((int)reader.BytesConsumed);

            if (leftover.Length == buffer.Length)
            {
                // TODO log change in size.
                Array.Resize(ref buffer, buffer.Length * 2);
            }

            leftover.CopyTo(buffer);
            bytesRead = stream.Read(buffer.AsSpan(leftover.Length));
        }
        else
        {
            bytesRead = stream.Read(buffer);
        }

        reader = new Utf8JsonReader(buffer, isFinalBlock: bytesRead == 0, reader.CurrentState);
    }
}
