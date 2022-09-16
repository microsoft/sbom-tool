// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

/// <summary>
/// Utility methods for parsing that are shared by all parsers.
/// </summary>
internal class ParserUtils
{
    private const string AlgorithmProperty = "algorithm";
    private const string ChecksumValueProperty = "checksumValue";

    /// <summary>
    /// Read the next JSON token in the reader from the input buffer.
    /// If the buffer is small and doesn't contain all the text for the next token, 
    /// a call to GetMoreBytesFromStream is made to read more data into the buffer.
    /// </summary>
    /// <exception cref="EndOfStreamException"></exception>
    public static void Read(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
        }

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

    /// <summary>
    /// Asserts if the reader is at the current expected token.
    /// </summary>
    /// <exception cref="ParserException"></exception>
    internal static void AssertTokenType(Stream stream, ref Utf8JsonReader reader, JsonTokenType expectedTokenType)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        if (reader.TokenType != expectedTokenType)
        {
            throw new ParserException($"Expected a '{Constants.JsonTokenStrings[(byte)expectedTokenType]}' token at position {stream.Position}");
        }
    }

    /// <summary>
    /// Assert that the current token is either one of the tokens specified 
    /// in the <paramref name="expectedTokenTypes"/>.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="reader"></param>
    /// <param name="expectedTokenTypes"></param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ParserException"></exception>
    internal static void AssertEitherTokenTypes(Stream stream, ref Utf8JsonReader reader, JsonTokenType[] expectedTokenTypes)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        foreach (var tokenType in expectedTokenTypes)
        {
            if (reader.TokenType == tokenType)
            {
                // Found at least one of the expected tokens.
                return;
            }
        }

        // If control ends up here, no expected tokens matched.
        var expectedTokenTypesStr = string.Join(",", expectedTokenTypes.Select(t => Constants.JsonTokenStrings[(byte)t]));
        throw new ParserException($"Expected either one of a '{expectedTokenTypesStr}' token at position {stream.Position}");
    }

    /// <summary>
    /// Helper method to move the reader from a None token type to the next available token.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="reader"></param>
    internal static void SkipNoneTokens(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        while (reader.TokenType == JsonTokenType.None)
        {
            Read(stream, ref buffer, ref reader);
        }
    }

    /// <summary>
    /// Skips the first [ token from the stream.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="reader"></param>
    internal static void SkipFirstArrayToken(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        // Ensure first value is an array and read that so that we are the { token.
        SkipNoneTokens(stream, ref buffer, ref reader);
        AssertTokenType(stream, ref reader, JsonTokenType.StartArray);
        Read(stream, ref buffer, ref reader);
        GetMoreBytesFromStream(stream, ref buffer, ref reader);
    }

    /// <summary>
    /// Skips the first { token from the stream.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="reader"></param>
    internal static void SkipFirstObjectToken(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        // Ensure first value is an array and read that so that we are the { token.
        SkipNoneTokens(stream, ref buffer, ref reader);
        AssertTokenType(stream, ref reader, JsonTokenType.StartObject);
     }

    /// <summary>
    /// Helper method that can be used to display a byte readonlyspan for logging.
    /// </summary>
    /// <returns></returns>
    internal static string GetStringValue(ReadOnlySpan<byte> valueSpan)
    {
        return Encoding.UTF8.GetString(valueSpan.ToArray());
    }

    /// <summary>
    /// Returns the next string value for a given property, for example:
    /// 
    /// { "TestProperty": "TestProperty Value" }
    /// 
    /// Will return "TestProperty Value".
    /// </summary>
    /// <param name="reader"></param>
    /// <param name="buffer"></param>
    /// <returns>The next string value.</returns>
    internal static string ParseNextString(Stream stream, ref Utf8JsonReader reader)
    {
        AssertTokenType(stream, ref reader, JsonTokenType.String);
        return reader.GetString();
    }

    /// <summary>
    /// Reads and discards any given value for a property. If the value is an arry or object
    /// it reads and discards the whole array or object
    /// </summary>
    /// <param name="reader"></param>
    /// <param name="buffer"></param>
    internal static void SkipProperty(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.PropertyName)
        {
            Read(stream, ref buffer, ref reader);
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
                    Read(stream, ref buffer, ref reader);
                }
                else
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// If the buffer still has some space left, reads the stream into the remaining buffer space.
    /// If the buffer is full, doubles the size of the buffer and then performs the read.
    /// If the buffer is empty, reads the stream into the buffer fully.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="reader"></param>
    public static void GetMoreBytesFromStream(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        if (buffer is null || buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(buffer)} value can't be null or of 0 length.");
        }

        int bytesRead;
        if (reader.BytesConsumed < buffer.Length)
        {
            ReadOnlySpan<byte> leftover = buffer.AsSpan((int)reader.BytesConsumed);

            if (leftover.Length == buffer.Length)
            {
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

    /// <summary>
    /// Returns the next boolean value for a given property, for example:
    /// 
    /// { "TestProperty": false }
    /// 
    /// Will return false.
    /// </summary>
    /// <param name="reader"></param>
    /// <param name="buffer"></param>
    /// <returns>The next boolean value.</returns>
    internal static bool ParseNextBoolean(Stream stream, ref Utf8JsonReader reader)
    {
        AssertEitherTokenTypes(stream, ref reader, new JsonTokenType[] { JsonTokenType.True, JsonTokenType.False });
        return reader.GetBoolean();
    }

    /// <summary>
    /// Parse an array of strings. For example
    /// "prop": ["Value1", "Value2", "Value3"].
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="reader"></param>
    /// <param name="buffer"></param>
    /// <returns></returns>
    internal static List<string> ParseListOfStrings(Stream stream, ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var strings = new List<string>();

        // Read the opening [ of the array
        AssertTokenType(stream, ref reader, JsonTokenType.StartArray);

        while (reader.TokenType != JsonTokenType.EndArray)
        {
            Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            strings.Add(reader.GetString());
        }

        AssertTokenType(stream, ref reader, JsonTokenType.EndArray);
        return strings;
    }

    /// <summary>
    /// Parse a <see cref="Checksum"/> object.
    /// </summary>
    /// <param name="reader"></param>
    /// <param name="buffer"></param>
    /// <returns></returns>
    internal static Checksum ParseChecksumObject(Stream stream, ref Utf8JsonReader reader, ref byte[] buffer)
    {
        var checksum = new Checksum();

        // Read the opening { of the object
        AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

        // Move to the first property token
        Read(stream, ref buffer, ref reader);
        AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);

        while (reader.TokenType != JsonTokenType.EndObject)
        {
            switch (reader.GetString())
            {
                case AlgorithmProperty:
                    Read(stream, ref buffer, ref reader);
                    checksum.Algorithm = ParseNextString(stream, ref reader);
                    break;

                case ChecksumValueProperty:
                    Read(stream, ref buffer, ref reader);
                    checksum.ChecksumValue = ParseNextString(stream, ref reader);
                    break;

                default:
                    SkipProperty(stream, ref buffer, ref reader);
                    break;
            }

            // Read the end } of this object or the next property name.
            Read(stream, ref buffer, ref reader);
        }

        AssertTokenType(stream, ref reader, JsonTokenType.EndObject);

        return checksum;
    }
}
