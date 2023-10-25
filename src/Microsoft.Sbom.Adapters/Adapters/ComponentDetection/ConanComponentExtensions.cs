// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

internal static class ConanComponentExtensions
{
    public static SbomPackage? ToSbomPackage(this ConanComponent conanComponent)
    {
        var lst = new List<Checksum>();
        if (!string.IsNullOrEmpty(conanComponent.Md5Hash))
        {
            lst.Add(new Checksum
            {
                Algorithm = Contracts.Enums.AlgorithmName.MD5,
                ChecksumValue = conanComponent.Md5Hash
            });
        }

        if (!string.IsNullOrEmpty(conanComponent.Sha1Hash))
        {
            lst.Add(new Checksum
            {
                Algorithm = Contracts.Enums.AlgorithmName.SHA1,
                ChecksumValue = conanComponent.Sha1Hash
            });
        }

        return new()
        {
            Id = conanComponent.Id,
            PackageUrl = conanComponent.PackageUrl?.ToString(),
            PackageName = conanComponent.Name,
            PackageVersion = conanComponent.Version,
            PackageSource = conanComponent.PackageSourceURL,
            FilesAnalyzed = false,
            Checksum = lst,
            Type = "conan"
        };
    }
}
