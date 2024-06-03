// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text.Json;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// This implements the custom serializer for writing json output by the Manifest
/// tool. This serializer is optimized for writing a lot of array values, and some
/// additional metadata.
///
/// It holds a <see cref="Utf8JsonWriter"/> object inside which is disposable.
/// </summary>
public interface IManifestToolJsonSerializer : IAsyncDisposable, IDisposable
{
    /// <summary>
    /// Writes the start JSON object. Must be called before writing to the serializer.
    /// </summary>
    public void StartJsonObject();

    /// <summary>
    /// Writes the end JSON object. Must be called after finishing writing to
    /// the serializer to close the json object.
    /// </summary>
    public void FinalizeJsonObject();

    /// <summary>
    /// Start an array object with the header string as the key.
    /// </summary>
    /// <param name="arrayHeader">They key to the array.</param>
    public void StartJsonArray(string arrayHeader);

    /// <summary>
    /// End the current array. Throws if there is currently no array object being written to.
    /// </summary>
    public void EndJsonArray();

    /// <summary>
    /// This writes a json document to the underlying stream.
    /// We also call dispose on the JsonDocument once we finish writing.
    /// </summary>
    /// <param name="jsonDocument">The json document.</param>
    public void Write(JsonDocument jsonDocument);

    /// <summary>
    /// Write a json string object. This usually is some metadata about the document
    /// that is generated.
    /// </summary>
    void WriteJsonString(string jsonString);
}
