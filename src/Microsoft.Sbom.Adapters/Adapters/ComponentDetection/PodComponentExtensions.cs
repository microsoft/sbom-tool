// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="PodComponent" />.
/// </summary>
internal static class PodComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="PodComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="podComponent">The <see cref="PodComponent" /> to convert.</param>
    /// <param name="license">The license to use.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage? ToSbomPackage(this PodComponent podComponent, string? license = null) => new()
    {
        Id = podComponent.Id,
        PackageUrl = podComponent.PackageUrl?.ToString(),
        PackageName = podComponent.Name,
        PackageVersion = podComponent.Version,
        PackageSource = podComponent.SpecRepo,
        LicenseInfo = string.IsNullOrWhiteSpace(license) ? null : new LicenseInfo
        {
            Concluded = license,
        },
        FilesAnalyzed = false,
        Type = "pod",
    };
}
