// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="OtherComponent"/>.
/// </summary>
internal static class OtherComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="OtherComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this OtherComponent otherComponent) => new()
    {
        Id = otherComponent.Id,
        PackageUrl = otherComponent.PackageUrl?.ToString(),
        PackageName = otherComponent.Name,
        PackageVersion = otherComponent.Version,
        PackageSource = otherComponent.DownloadUrl?.ToString(),
        Checksum = new[]
        {
            new Checksum { ChecksumValue = otherComponent.Hash },
        },
        FilesAnalyzed = false,
        Type = "other"
    };
}
