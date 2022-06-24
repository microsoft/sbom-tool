// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Output
{
    /// <summary>
    /// This implements the custom serializer for writing json output by the Manifest 
    /// tool. This serializer is optimized for writing a lot of array values, and some 
    /// additional metadata.
    /// 
    /// It holds a <see cref="Utf8JsonWriter"/> object inside which is disposable.
    /// </summary>
    public sealed class ManifestToolJsonSerializer : IManifestToolJsonSerializer
    {
        private Utf8JsonWriter jsonWriter;

        public ManifestToolJsonSerializer(Stream stream)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            jsonWriter = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        }

        public void Dispose()
        {
            jsonWriter?.Dispose();
            jsonWriter = null;
        }

        public async ValueTask DisposeAsync()
        {
            if (jsonWriter != null)
            {
                await jsonWriter.DisposeAsync().ConfigureAwait(false);
            }

            jsonWriter = null;
        }

        /// <summary>
        /// This writes a json document to the underlying stream. 
        /// We also call dispose on the JsonDocument once we finish writing.
        /// </summary>
        /// <param name="jsonDocument">The json document.</param>
        public void Write(JsonDocument jsonDocument)
        {
            if (jsonDocument == null)
            {
                return;
            }

            using (jsonDocument)
            {
                jsonDocument.WriteTo(jsonWriter);
            }

            // If the pending buffer size is greater than a megabyte, flush the stream.
            if (jsonWriter.BytesPending > 1_000_000)
            {
                jsonWriter.Flush();
            }
        }

        /// <summary>
        /// Write a json string object. This usually is some metadata about the document
        /// that is generated.
        /// </summary>
        public void WriteJsonString(string jsonString)
        {
            if (!string.IsNullOrEmpty(jsonString))
            {
                using JsonDocument document = JsonDocument.Parse(jsonString);
                foreach (JsonProperty property in document.RootElement.EnumerateObject())
                {
                    property.WriteTo(jsonWriter);
                }
            }
        }

        /// <summary>
        /// Writes the start JSON object. Must be called before writing to the serializer.
        /// </summary>
        public void StartJsonObject() => jsonWriter.WriteStartObject();

        /// <summary>
        /// Writes the end JSON object. Must be called after finishing writing to 
        /// the serializer to close the json object.
        /// </summary>
        public void FinalizeJsonObject() => jsonWriter.WriteEndObject();

        /// <summary>
        /// Start an array object with the header string as the key.
        /// </summary>
        /// <param name="arrayHeader">They key to the array.</param>
        public void StartJsonArray(string arrayHeader) => jsonWriter.WriteStartArray(JsonEncodedText.Encode(arrayHeader));

        /// <summary>
        /// End the current array. Throws if there is currently no array object being written to.
        /// </summary>
        public void EndJsonArray() => jsonWriter.WriteEndArray();
    }
}
