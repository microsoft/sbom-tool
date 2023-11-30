// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

/// <summary>
/// SPDX 2.2 format External Document reference.
/// </summary>
public class SpdxExternalDocumentReference
{
    /// <summary>
    /// Gets or sets unique Identifier for ExternalDocumentReference in SPDX document.
    /// </summary>
    [JsonPropertyName("externalDocumentId")]
    public string ExternalDocumentId { get; set; }

    /// <summary>
    /// Gets or sets document namespace of the input SBOM.
    /// </summary>
    [JsonPropertyName("spdxDocument")]
    public string SpdxDocument { get; set; }

    /// <summary>
    /// Gets or sets checksum values for External SBOM file.
    /// </summary>
    [JsonPropertyName("checksum")]
    public Checksum Checksum { get; set; }
}
