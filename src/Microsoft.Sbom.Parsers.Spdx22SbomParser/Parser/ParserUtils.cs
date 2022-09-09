// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Text.Json;
using System.Text;
using System;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;

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

        if (!reader.Read())
        {
            // Not enough of the JSON is in the buffer to complete a read.
            GetMoreBytesFromStream(stream, ref buffer, ref reader);
        }
    }

    public static void RemoveBytesRead(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        if (reader.BytesConsumed > 0)
        {
            ReadOnlySpan<byte> leftover = buffer.AsSpan((int)reader.BytesConsumed);

            leftover.CopyTo(buffer);
            stream.Read(buffer.AsSpan(leftover.Length));
        }
    }

    internal static string GetStringValue(ReadOnlySpan<byte> valueSpan)
    {
        return Encoding.UTF8.GetString(valueSpan.ToArray());
    }

    private static void GetMoreBytesFromStream(Stream stream, ref byte[] buffer, ref Utf8JsonReader reader)
    {
        int bytesRead;
        if (reader.BytesConsumed < buffer.Length)
        {
            ReadOnlySpan<byte> leftover = buffer.AsSpan((int)reader.BytesConsumed);

            if (leftover.Length == buffer.Length && buffer.Length < Constants.MaxReadBufferSize)
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
