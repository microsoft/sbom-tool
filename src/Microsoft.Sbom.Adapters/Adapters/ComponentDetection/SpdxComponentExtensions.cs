// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="SpdxComponent"/>.
    /// </summary>
    internal static class SpdxComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="SpdxComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this SpdxComponent spdxComponent) => new ()
        {
            Id = spdxComponent.Id,
            PackageName = spdxComponent.Name,
            PackageUrl = spdxComponent.PackageUrl?.ToString(),
            PackageVersion = spdxComponent.SpdxVersion,
            Checksum = new[]
            {
                new Checksum
                {
                    Algorithm = AlgorithmName.SHA1,
                    ChecksumValue = spdxComponent.Checksum
                },
            },
            FilesAnalyzed = false,
            Type = "spdx"
        };
    }
}
