// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// Provides a <see cref="ManifestConfig"/> object for a given
/// SBOM format implementation.
/// </summary>
public interface IManifestConfigHandler
{
    /// <summary>
    /// Tries to parse the SBOM configuration based on the internal implementation details.
    /// If the SBOM format is supported by the current implementation, populates the manifestConfig
    /// object and returns true, or else returns false.
    /// </summary>
    /// <param name="manifestConfig"></param>
    /// <returns></returns>
    bool TryGetManifestConfig(out ISbomConfig sbomConfig);
}
