// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Extensions methods for <see cref="ConanComponent" />.
/// </summary>
internal static class ConanComponentExtension
{
    /// <summary>
    /// Converts a <see cref="ConanComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="conanComponent">The <see cref="ConanComponent" /> to convert.</param>
    /// <param name="license">The license to use for the <see cref="SbomPackage" />.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this ConanComponent conanComponent, string? license = null)
    {
        var lst = new List<Checksum>();
        if (!string.IsNullOrEmpty(conanComponent.Md5Hash))
        {
            lst.Add(
                new Checksum
                {
                    Algorithm = AlgorithmName.MD5, ChecksumValue = conanComponent.Md5Hash,
                });
        }

        if (!string.IsNullOrEmpty(conanComponent.Sha1Hash))
        {
            lst.Add(
                new Checksum
                {
                    Algorithm = AlgorithmName.SHA1, ChecksumValue = conanComponent.Sha1Hash,
                });
        }

        return new SbomPackage
        {
            Id = conanComponent.Id,
            PackageUrl = conanComponent.PackageUrl?.ToString(),
            PackageName = conanComponent.Name,
            PackageVersion = conanComponent.Version,
            PackageSource = conanComponent.PackageSourceURL,
            FilesAnalyzed = false,
            LicenseInfo = string.IsNullOrWhiteSpace(license) ? null : new LicenseInfo
            {
                Concluded = license,
            },
            Checksum = lst,
            Type = "conan",
        };
    }
}
