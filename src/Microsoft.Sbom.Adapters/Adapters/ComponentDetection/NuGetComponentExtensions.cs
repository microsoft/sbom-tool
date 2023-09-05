// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="NuGetComponent"/>.
/// </summary>
internal static class NuGetComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="NuGetComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    /// <param name="license"> License information for the package that component that is being converted.</param>
    public static SbomPackage? ToSbomPackage(this NuGetComponent nuGetComponent, string? license = null) => new ()
    {
        Id = nuGetComponent.Id,
        PackageUrl = nuGetComponent.PackageUrl?.ToString(),
        PackageName = nuGetComponent.Name,
        PackageVersion = nuGetComponent.Version,
        Supplier = nuGetComponent.Authors?.Any() == true ? $"Organization: {nuGetComponent.Authors.First()}" : null,
        LicenseInfo = string.IsNullOrWhiteSpace(license) ? null : new LicenseInfo { Concluded = license },
        FilesAnalyzed = false,
        Type = "nuget"
    };
}
