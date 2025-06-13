// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// Implementations of this interface provide mergeable SBOM content based on a given input stream.
/// </summary>
public interface IMergeableContentProviderInternal : IMergeableContentProvider
{
    /// <summary>
    /// Extract the <paramref name="mergeableContent"/> from the given <paramref name="stream"/>.
    /// </summary>
    /// <param name="stream">The stream containing the content.</param>
    /// <param name="mergeableContent">The content if reading was successful, otherwise null.</param>
    /// <returns>true if successful, otherwise false.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public bool TryGetContent(Stream stream, out MergeableContent? mergeableContent);
}
