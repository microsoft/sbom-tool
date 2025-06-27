// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System.Text.Json.Serialization;

// This class uses JSON serialization attributes to enforce the SPDX 2.x format
// Metadata fields tagged as required are required by the SPDX 2.x specification.
public class SPDX22RequiredProperties
{
    // These attributes are required by the SPDX 2.x spec.
    [JsonRequired]
    [JsonPropertyName("spdxVersion")]
    public string Version { get; set; }

    [JsonRequired]
    [JsonPropertyName("dataLicense")]
    public string DataLicense { get; set; }

    [JsonRequired]
    [JsonPropertyName("SPDXID")]
    public string SPDXID { get; set; }

    [JsonRequired]
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonRequired]
    [JsonPropertyName("documentNamespace")]
    public string DocumentNamespace { get; set; }

    [JsonRequired]
    [JsonPropertyName("creationInfo")]
    public CreationInfo CreationInfo { get; set; }
}
