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
    public static SbomPackage? ToSbomPackage(this NuGetComponent nuGetComponent, string? license = null)
    {
        var sbomPackage = new SbomPackage
        {
            Id = nuGetComponent.Id,
            PackageUrl = nuGetComponent.PackageUrl?.ToString(),
            PackageName = nuGetComponent.Name,
            PackageVersion = nuGetComponent.Version,
            Supplier = nuGetComponent.Authors?.Any() == true ? $"Organization: {nuGetComponent.Authors.First()}" : null,
            FilesAnalyzed = false,
            Type = "nuget"
        };

        if (license != null)
        {
            sbomPackage.LicenseInfo = new LicenseInfo
            {
                Concluded = license,
            };
        }

        return sbomPackage;
    }
}