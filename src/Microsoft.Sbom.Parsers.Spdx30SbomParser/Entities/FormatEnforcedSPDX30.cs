// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

using System.Collections.Generic;
using System.Text.Json.Serialization;

// This class uses JSON serialization attributes to enforce the SPDX 3.x format
// Metadata fields tagged as required are required by the SPDX 3.x specification.
// SPDX 3.x specification link, only the Core Profile is mandatory: https://spdx.github.io/spdx-spec/v3.0.1/conformance/
// The SPDX 3.x documents also have to be a strict subset of JSON-LD https://json-ld.org/
public class FormatEnforcedSPDX30
{
    /// <summary>
    /// Indicates that this is an SPDX document, and this provided URL tells us how to decode it.
    /// A requirement for JSON-LD documents.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("@context")]
    public string Context { get; set; }

    /// <summary>
    /// A requirement for JSON-LD documents.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("@graph")]
    public IEnumerable<Element> Graph { get; set; }

    /// <summary>
    /// Required as part of the Core profile.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("spdxId")]
    public string SpdxId { get; set; }

    /// <summary>
    /// Required as part of the Core profile.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("creationInfo")]
    public CreationInfo CreationInfo { get; set; }
}
