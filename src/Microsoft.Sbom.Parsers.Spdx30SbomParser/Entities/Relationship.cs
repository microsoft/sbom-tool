// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Extensions.Entities;
using RelationshipType = Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums.RelationshipType;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Defines relationships between elements in the current SBOM.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Relationship/
/// </summary>
public class Relationship : Element
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Relationship"/> class.
    /// </summary>
    public Relationship()
    {
        Type = nameof(Relationship);
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("completeness")]
    public object Completeness { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("endTime")]
    public DateTime EndTime { get; set; }

    /// <summary>
    /// Gets or sets the id of the source element with whom the target element has a relationship.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("from")]
    public string From { get; set; }

    [JsonRequired]
    [JsonPropertyName("relationshipType")]
    public RelationshipType RelationshipType { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("startTime")]
    public DateTime StartTime { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("to")]
    public List<string> To { get; set; }
}
