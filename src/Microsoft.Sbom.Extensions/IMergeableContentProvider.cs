// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions;

using Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// Implementations of this interface provide mergeable SBOM content based on a given input file.
/// </summary>
public interface IMergeableContentProvider
{
    /// <summary>
    /// The ManifestInfo supported by this provider
    /// </summary>
    public ManifestInfo ManifestInfo { get; }

    /// <summary>
    /// Extract the <paramref name="mergeableContents"/> from the given <paramref name="filePath"/>.
    /// </summary>
    /// <param name="filePath">The file on disk. Should be opened read-only, read-sharable.</param>
    /// <param name="mergeableContent">The content if reading was successful, otherwise null.</param>
    /// <returns>true if successful, otherwise false.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public bool TryGetContent(string filePath, out MergeableContent? mergeableContent);
}
