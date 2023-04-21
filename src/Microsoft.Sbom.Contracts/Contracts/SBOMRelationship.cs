// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Defines a relationship between SBOM elements.
/// </summary>
public class SBOMRelationship
{
    /// <summary>
    /// Defines the relationship between the source and target element.
    /// </summary>
    public string RelationshipType { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    public string TargetElementId { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    public string SourceElementId { get; set; }
}