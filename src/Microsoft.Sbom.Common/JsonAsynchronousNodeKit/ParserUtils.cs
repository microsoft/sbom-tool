// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;

namespace Microsoft.Sbom.JsonAsynchronousNodeKit;

#nullable enable

/// <summary>
/// Utility methods for parsing that are shared by all parsers.
/// </summary>
internal static class ParserUtils
{
    /// <summary>
    /// Read the next JSON token in the reader from the input buffer.
    /// If the buffer is small and doesn't contain all the text for the next token,
    /// a call to GetMoreBytesFromStream is made to read more data into the buffer.
    /// </summary>
    /// <param name="stream">The <see cref="Stream"/> to read from.</param>
    /// <param name="buffer">The buffer to  read from.</param>
    /// <param name="reader">The <see cref="Utf8JsonReader"/> to read from.</param>
    /// <exception cref="EndOfStreamException">If the stream unexpectedly ended.</exception>
    /// <exception cref="ArgumentNullException">If an argument was null when that is not allowed.</exception>
    internal static void Read(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (stream == null)
        {
            throw new ArgumentNullException(nameof(stream));
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
    /// <param name="stream">The <see cref="Stream"/> to read from.</param>
    /// <param name="reader">The <see cref="Utf8JsonReader"/> to read from.</param>
    /// <param name="expectedTokenType">The expected token type.</param>
    /// <exception cref="ParserException">When the token was not as expected.</exception>
    internal static void AssertTokenType(Stream stream, ref Utf8JsonReader reader, JsonTokenType expectedTokenType)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        if (reader.TokenType != expectedTokenType)
        {
            throw new ParserException($"Expected a '{Constants.JsonTokenStrings[(byte)expectedTokenType]}' token at position {stream.Position} but got {Constants.JsonTokenStrings[(byte)reader.TokenType]}");
        }
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
    /// Reads and discards any given value for a property. If the value is an array or object
    /// it reads and discards the whole array or object.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="reader"></param>
    internal static void SkipProperty(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var arrayCount = 1;
            while (true)
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    arrayCount--;
                    if (arrayCount == 0)
                    {
                        return;
                    }
                }

                Read(stream, ref buffer, ref reader);

                if (reader.TokenType == JsonTokenType.StartArray)
                {
                    arrayCount++;
                }
            }
        }
        else if (reader.TokenType == JsonTokenType.StartObject)
        {
            var objectCount = 1;
            while (true)
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    objectCount--;
                    if (objectCount == 0)
                    {
                        return;
                    }
                }

                Read(stream, ref buffer, ref reader);

                if (reader.TokenType == JsonTokenType.StartObject)
                {
                    objectCount++;
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
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>"
    internal static void GetMoreBytesFromStream(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
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

            // stream.Read doesn't always return the whole buffer length, so we need to fill the rest
            if (bytesRead + leftover.Length != buffer.Length)
            {
                bytesRead = stream.Read(buffer.AsSpan(bytesRead + leftover.Length));
            }
        }
        else
        {
            bytesRead = stream.Read(buffer);

            // stream.Read doesn't always return the whole buffer length, so we need to fill the rest
            if (bytesRead < buffer.Length)
            {
                bytesRead = stream.Read(buffer.AsSpan(bytesRead));
            }
        }

        reader = new Utf8JsonReader(buffer, isFinalBlock: bytesRead == 0, reader.CurrentState);
    }

    internal static JsonObject ParseObject(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        AssertTokenType(stream, ref reader, JsonTokenType.StartObject);

        var node = new JsonObject();

        JsonNode? value = null;
        while (reader.TokenType != JsonTokenType.EndObject || value is JsonObject)
        {
            Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            AssertTokenType(stream, ref reader, JsonTokenType.PropertyName);
            var propertyName = reader.GetString()!;
            Read(stream, ref buffer, ref reader);
            value = ParseValue(stream, ref buffer, ref reader);
            node.Add(propertyName, value);
        }

        return node;
    }

    internal static JsonNode? ParseValue(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader) => reader.TokenType switch
    {
        JsonTokenType.StartObject => ParseObject(stream, ref buffer, ref reader),
        JsonTokenType.StartArray => ParseArray(stream, ref buffer, ref reader),
        JsonTokenType.Number => reader.GetDouble(),
        JsonTokenType.String => reader.GetString(),
        JsonTokenType.True => true,
        JsonTokenType.False => false,
        JsonTokenType.Null => null,
        JsonTokenType.None or
        JsonTokenType.EndObject or
        JsonTokenType.EndArray or
        JsonTokenType.PropertyName or
        JsonTokenType.Comment or
        _ => throw new InvalidOperationException($"Unexpected token type {reader.TokenType}"),
    };

    internal static JsonArray ParseArray(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        AssertTokenType(stream, ref reader, JsonTokenType.StartArray);

        var node = new JsonArray();

        JsonNode? value = null;
        while (reader.TokenType != JsonTokenType.EndArray || value is JsonArray)
        {
            Read(stream, ref buffer, ref reader);
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            value = ParseValue(stream, ref buffer, ref reader);
            node.Add(value);
        }

        return node;
    }
}
