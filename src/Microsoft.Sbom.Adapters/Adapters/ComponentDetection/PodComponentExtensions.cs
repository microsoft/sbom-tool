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
    /// <param name="component">The <see cref="ExtendedScannedComponent"/> version of the PodComponent</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage? ToSbomPackage(this PodComponent podComponent, ExtendedScannedComponent component) => new()
    {
        Id = podComponent.Id,
        PackageUrl = podComponent.PackageUrl?.ToString(),
        PackageName = podComponent.Name,
        PackageVersion = podComponent.Version,
        PackageSource = podComponent.SpecRepo,
        LicenseInfo = string.IsNullOrWhiteSpace(component.LicenseConcluded) ? null : new LicenseInfo
        {
            Concluded = component.LicenseConcluded,
        },
        FilesAnalyzed = false,
        Type = "pod",
        DependOn = null
    };
}
