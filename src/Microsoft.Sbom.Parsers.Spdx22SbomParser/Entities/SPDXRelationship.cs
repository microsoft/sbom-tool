// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

/// <summary>
/// Defines relationships between elements in the current SBOM.
/// </summary>
public class SPDXRelationship
{
    /// <summary>
    /// Gets or sets defines the type of the relationship between the source and the target element.
    /// </summary>
    [JsonPropertyName("relationshipType")]
    public string RelationshipType { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("relatedSpdxElement")]
    public string TargetElementId { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("spdxElementId")]
    public string SourceElementId { get; set; }
}
