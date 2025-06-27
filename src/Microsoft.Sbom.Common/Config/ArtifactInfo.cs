// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Config;

/// <summary>
/// Describes a single artifact that is an input to the consolidation workflow.
/// </summary>
public class ArtifactInfo
{
    /// <summary>
    /// If the manifest folder is external to the artifact, this tells us where to find it.
    /// </summary>
    public string? ExternalManifestDir { get; set; }

    /// <summary>
    /// If true, files missing from the artifact will not cause an error.
    /// </summary>
    public bool? IgnoreMissingFiles { get; set; }

    /// <summary>
    /// If true, we will skip the signing check for this artifact. NOT RECOMMENDED for production use.
    /// </summary>
    public bool? SkipSigningCheck { get; set; }
}
