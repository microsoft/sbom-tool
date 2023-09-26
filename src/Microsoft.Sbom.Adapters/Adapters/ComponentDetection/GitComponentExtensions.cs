// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Extensions methods for <see cref="GitComponent" />.
/// </summary>
internal static class GitComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="GitComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="gitComponent">The <see cref="GitComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this GitComponent gitComponent) => new()
    {
        Id = gitComponent.Id,
        PackageName = gitComponent.Id,
        PackageUrl = gitComponent.PackageUrl?.ToString(),
        PackageSource = gitComponent.RepositoryUrl?.ToString(),
        Checksum = new[]
        {
            new Checksum
            {
                Algorithm = AlgorithmName.SHA1, ChecksumValue = gitComponent.CommitHash,
            },
        },
        FilesAnalyzed = false,
        Type = "git-package",
    };
}
