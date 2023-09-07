// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="PodComponent"/>.
/// </summary>
internal static class PodComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="PodComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this PodComponent podComponent, string? license = null) => new()
    {
        Id = podComponent.Id,
        PackageUrl = podComponent.PackageUrl?.ToString(),
        PackageName = podComponent.Name,
        PackageVersion = podComponent.Version,
        PackageSource = podComponent.SpecRepo,
        LicenseInfo = string.IsNullOrWhiteSpace(license) ? null : new LicenseInfo { Concluded = license },
        FilesAnalyzed = false,
        Type = "pod"
    };
}
