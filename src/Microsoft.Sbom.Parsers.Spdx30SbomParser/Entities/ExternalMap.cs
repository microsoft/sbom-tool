// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// SPDX 3.0 format External Map (equivalent of externalDocumentRef in SPDX 2.2).
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/ExternalMap/
/// </summary>
public class ExternalMap : Element
{
    public ExternalMap()
    {
        Type = nameof(ExternalMap);
    }

    /// <summary>
    /// This will not be used in the actual SBOM generation, therefore deserialization/serialization to a specific type is not required.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("definingArtifact")]
    public object DefiningArtifact { get; set; }

    /// <summary>
    /// Gets or sets unique Identifier for ExternalMap in SPDX document.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("externalSpdxId")]
    public string ExternalSpdxId { get; set; }

    /// <summary>
    /// Gets or sets url value of package location.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("locationHint")]
    public string LocationHint { get; set; }
}
