// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// Defines relationships between elements in the current SBOM.
/// </summary>
public class Relationship
{
    /// <summary>
    /// Gets or sets defines the type of the relationship between the source and the target element.
    /// </summary>
    public RelationshipType RelationshipType { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    public string TargetElementId { get; set; }

    /// <summary>
    /// Gets or sets iD of the reference for the target element, if the element is referenced from external document.
    /// </summary>
    public string TargetElementExternalReferenceId { get; set; }

    /// <summary>
    /// Gets or sets the id of the target element with whom the source element has a relationship.
    /// </summary>
    public string SourceElementId { get; set; }
}