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
    /// <param name="license">The license to use.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this PipComponent pipComponent, string? licenseConcluded = null) => new()
    {
        Id = pipComponent.Id,
        PackageUrl = pipComponent.PackageUrl?.ToString(),
        PackageName = pipComponent.Name,
        PackageVersion = pipComponent.Version,
        LicenseInfo = string.IsNullOrWhiteSpace(licenseConcluded) ? null : new LicenseInfo
        {
            Concluded = licenseConcluded,
        },
        FilesAnalyzed = false,
        Type = "python",
    };
}
