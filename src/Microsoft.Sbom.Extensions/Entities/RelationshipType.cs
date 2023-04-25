// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// Defines the type of <see cref="Relationship"/> between the source and the 
/// target element.
/// </summary>
/// <remarks>
/// See https://spdx.github.io/spdx-spec/relationships-between-SPDX-elements/.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RelationshipType
{
    /// <summary>
    /// The source element contains the target element.
    /// `Is to be used when SPDXRef-A contains SPDXRef-B.`
    /// </summary>
    /// <example>
    /// An ARCHIVE file bar.tgz contains a SOURCE file foo.c.
    /// </example>
    CONTAINS,

    /// <summary>
    /// The source element depends on the target element.
    /// `Is to be used when SPDXRef-A depends on SPDXRef-B.`
    /// </summary>
    /// <example>
    /// Package A depends on the presence of package B in order to build and run
    /// </example>
    DEPENDS_ON,

    /// <summary>
    /// The source element describes the target element.
    /// </summary>
    /// <example>
    /// An SPDX document WildFly.spdx describes package ‘WildFly’. 
    /// Note this is a logical relationship to help organize related items within 
    /// an SPDX document that is mandatory if more than one package or set of files 
    /// (not in a package) is present.
    /// </example>
    DESCRIBES,

    /// <summary>
    /// The source element is a prerequisite for the target element.
    /// </summary>
    /// <example>
    /// A library A is a prerequisite or dependency for B.
    /// </example>
    PREREQUISITE_FOR,

        /// <summary>
        /// The source element is described by the target element.
        /// </summary>
        /// <example>
        /// The package ‘WildFly’ is described by SPDX document WildFly.spdx.
        /// </example>
        DESCRIBED_BY,

        /// <summary>
        /// The source element is a patch for the target element.
        /// </summary>
        /// <example>
        /// A source file foo.diff is a patch file for source file foo.c.
        /// </example>
        PATCH_FOR
    }
}
