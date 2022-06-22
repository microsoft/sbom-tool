﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.SPDX22SBOMParser.Entities.Enums;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Defines relationships between elements in the current SBOM.
    /// </summary>
    public class SPDXRelationship
    {
        /// <summary>
        /// Defines the type of the relationship between the source and the target element.
        /// </summary>
        [JsonPropertyName("relationshipType")]
        public SPDXRelationshipType RelationshipType { get; set; }

        /// <summary>
        /// The id of the target element with whom the source element has a relationship.
        /// </summary>
        [JsonPropertyName("relatedSpdxElement")]
        public string TargetElementId { get; set; }

        /// <summary>
        /// The id of the target element with whom the source element has a relationship.
        /// </summary>
        [JsonPropertyName("spdxElementId")]
        public string SourceElementId { get; set; }
    }
}
