// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// Represents the mergeable content from an SBOM file in a format-agnostic way.
/// This is experimental and may change at any point in time without a corresponding
/// breaking version bump.
/// </summary>
public class MergeableContent
{
    /// <summary>
    /// The collection of SBOMPackage objects in the file.
    /// </summary>
    public IEnumerable<SbomPackage> Packages { get; }

    /// <summary>
    /// The collection of Relationship objects in the file.
    /// </summary>
    public IEnumerable<SbomRelationship> Relationships { get; }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <exception cref="ArgumentNullException"></exception>
    public MergeableContent(IEnumerable<SbomPackage> packages, IEnumerable<SbomRelationship> relationships)
    {
        Packages = packages ?? throw new ArgumentNullException(nameof(packages));
        Relationships = relationships ?? throw new ArgumentNullException(nameof(relationships));
    }
}
