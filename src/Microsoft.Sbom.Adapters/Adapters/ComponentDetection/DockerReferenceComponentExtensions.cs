// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Extensions methods for <see cref="DockerReferenceComponent" />.
/// </summary>
internal static class DockerReferenceComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="DockerReferenceComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="dockerReferenceComponent">The <see cref="DockerReferenceComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this DockerReferenceComponent dockerReferenceComponent) => new()
    {
        Id = dockerReferenceComponent.Id,
        PackageUrl = dockerReferenceComponent.PackageUrl?.ToString(),
        PackageName = dockerReferenceComponent.Digest,
        Checksum = new[]
        {
            new Checksum
            {
                Algorithm = AlgorithmName.SHA256, ChecksumValue = dockerReferenceComponent.Digest,
            },
        },
        FilesAnalyzed = false,
        Type = "docker",
    };
}
