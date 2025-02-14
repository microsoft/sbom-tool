// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

public class JsonDocumentCollection<T>
{
    public Dictionary<T, List<JsonDocument>> SerializersToJson { get; }

    public JsonDocumentCollection()
    {
        SerializersToJson = new Dictionary<T, List<JsonDocument>>();
    }

    public void AddJsonDocument(T key, JsonDocument document)
    {
        if (SerializersToJson.TryGetValue(key, out var jsonDocuments))
        {
            jsonDocuments.Add(document);
        }
        else
        {
            SerializersToJson.Add(key, new List<JsonDocument> { document });
        }
    }
}
