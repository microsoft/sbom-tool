// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.Internal;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="NpmComponent"/>.
/// </summary>
internal static class NpmComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="NpmComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this NpmComponent npmComponent, string? license = null)
    {
        var sbomPackage = new SbomPackage
        {
            Id = npmComponent.Id,
            PackageUrl = npmComponent.PackageUrl?.ToString(),
            PackageName = npmComponent.Name,
            PackageVersion = npmComponent.Version,
            Checksum = new[]
            {
                new Checksum { ChecksumValue = npmComponent.Hash },
            },
            Supplier = npmComponent.Author?.AsSupplier(),
            FilesAnalyzed = false,
            Type = "npm"
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

    /// <summary>
    /// Converts the <see cref="NpmAuthor"/> to an SPDX Supplier. 
    /// </summary>
    private static string AsSupplier(this NpmAuthor npmAuthor) => (npmAuthor.Name, npmAuthor.Email) switch
    {
        (string name, string email) => $"Organization: {name} ({email})",
        (string name, _) => $"Organization: {name}"
    };
}