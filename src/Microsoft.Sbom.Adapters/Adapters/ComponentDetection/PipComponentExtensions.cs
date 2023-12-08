// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="PipComponent" />.
/// </summary>
internal static class PipComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="PipComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="pipComponent">The <see cref="PipComponent" /> to convert.</param>
    /// <param name="component">The <see cref="ExtendedScannedComponent"/> version of the PipComponent</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this PipComponent pipComponent, ExtendedScannedComponent component) => new()
    {
        Id = pipComponent.Id,
        PackageUrl = pipComponent.PackageUrl?.ToString(),
        PackageName = pipComponent.Name,
        PackageVersion = pipComponent.Version,
        Supplier = string.IsNullOrEmpty(component.Supplier) ? null : $"Organization: {component.Supplier}",
        LicenseInfo = new LicenseInfo
        {
            Concluded = string.IsNullOrEmpty(component.LicenseConcluded) ? null : component.LicenseConcluded,
            Declared = string.IsNullOrEmpty(component.LicenseDeclared) ? null : component.LicenseDeclared,
        },
        FilesAnalyzed = false,
        Type = "python",
    };
}
