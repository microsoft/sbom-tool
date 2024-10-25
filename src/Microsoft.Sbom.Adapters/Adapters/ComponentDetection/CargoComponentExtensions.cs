// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Linq;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="CargoComponent" />.
/// </summary>
internal static class CargoComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="CargoComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="cargoComponent">The <see cref="CargoComponent" /> to convert.</param>
    /// <param name="component">The <see cref="ExtendedScannedComponent"/> version of the CargoComponent</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this CargoComponent cargoComponent, ExtendedScannedComponent component) => new()
    {
        Id = cargoComponent.Id,
        PackageUrl = cargoComponent.PackageUrl?.ToString(),
        PackageName = cargoComponent.Name,
        PackageVersion = cargoComponent.Version,
        LicenseInfo = string.IsNullOrWhiteSpace(component.LicenseConcluded) ? null : new LicenseInfo
        {
            Concluded = component.LicenseConcluded,
        },
        FilesAnalyzed = false,
        Type = "cargo",
        DependOn = component.AncestralReferrers?.FirstOrDefault()?.Id,
    };
}
