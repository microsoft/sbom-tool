// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;

/// <summary>
/// Defines the type of <see cref="SPDXRelationship"/> between the source and the 
/// target element.
/// 
/// Full definition here: https://spdx.github.io/spdx-spec/7-relationships-between-SPDX-elements/#71-relationship.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SPDXRelationshipType
{
    /// <summary>
    /// Is to be used when SPDXRef-A contains SPDXRef-B.
    /// </summary>
    CONTAINS,

    /// <summary>
    /// Is to be used when SPDXRef-A depends on SPDXRef-B.
    /// </summary>
    DEPENDS_ON,

    /// <summary>
    /// Is to be used when SPDXRef-DOCUMENT describes SPDXRef-A.
    /// </summary>
    DESCRIBES,

    /// <summary>
    /// Is to be used when SPDXRef-A is a prerequisite for SPDXRef-B.
    /// </summary>
    PREREQUISITE_FOR,

    /// <summary>
    /// Is to be used when SPDXRef-A is described by SPDXREF-Document.
    /// </summary>
    DESCRIBED_BY
}