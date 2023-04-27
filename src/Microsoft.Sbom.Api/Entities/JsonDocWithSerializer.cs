// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Entities;

/// <summary>
/// Represents a JsonDocument that needs to be written to a serializer. This is struct as its passed along
/// multiple times in functions, and we need it to be passed by value.
/// </summary>
public struct JsonDocWithSerializer
{
    private JsonDocument doc;
    private IManifestToolJsonSerializer serializer;

    public JsonDocument Document { get => doc; set => doc = value; }

    public IManifestToolJsonSerializer Serializer { get => serializer; set => serializer = value; }

    public JsonDocWithSerializer(JsonDocument doc, IManifestToolJsonSerializer serializer)
    {
        this.doc = doc;
        this.serializer = serializer;
    }

    public override bool Equals(object obj)
    {
        return obj is JsonDocWithSerializer other &&
               EqualityComparer<JsonDocument>.Default.Equals(doc, other.doc) &&
               EqualityComparer<IManifestToolJsonSerializer>.Default.Equals(serializer, other.serializer);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(doc, serializer);
    }

    public void Deconstruct(out JsonDocument doc, out IManifestToolJsonSerializer serializer)
    {
        doc = this.doc;
        serializer = this.serializer;
    }

    public static implicit operator (JsonDocument doc, IManifestToolJsonSerializer serializer)(JsonDocWithSerializer value)
    {
        return (value.doc, value.serializer);
    }

    public static implicit operator JsonDocWithSerializer((JsonDocument doc, IManifestToolJsonSerializer serializer) value)
    {
        return new JsonDocWithSerializer(value.doc, value.serializer);
    }
}