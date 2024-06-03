// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="LinuxComponent" />.
/// </summary>
internal static class LinuxComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="LinuxComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="linuxComponent">The <see cref="LinuxComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this LinuxComponent linuxComponent) => new()
    {
        Id = linuxComponent.Id,
        PackageUrl = linuxComponent.PackageUrl?.ToString(),
        PackageName = linuxComponent.Name,
        PackageVersion = linuxComponent.Version,
        FilesAnalyzed = false,
        Supplier = string.IsNullOrEmpty(linuxComponent.Author) ? null : $"Organization: {linuxComponent.Author}",
        LicenseInfo = string.IsNullOrEmpty(linuxComponent.License) ? null : new LicenseInfo
        {
            Concluded = linuxComponent.License
        },

        Type = "linux",
    };
}
