// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="VcpkgComponent" />.
/// </summary>
internal static class VcpkgComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="VcpkgComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="vcpkgComponent">The <see cref="VcpkgComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this VcpkgComponent vcpkgComponent) => new()
    {
        Id = vcpkgComponent.Id,
        PackageUrl = vcpkgComponent.PackageUrl?.ToString(),
        PackageName = vcpkgComponent.Name,
        PackageSource = vcpkgComponent.DownloadLocation,
        PackageVersion = vcpkgComponent.Version,
        FilesAnalyzed = false,
        Type = "vcpkg",
    };
}
