// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="DockerImageComponent"/>.
    /// </summary>
    internal static class DockerImageComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="DockerImageComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this DockerImageComponent dockerImageComponent) => new ()
        {
            Id = dockerImageComponent.Id,
            PackageUrl = dockerImageComponent.PackageUrl?.ToString(),
            PackageName = dockerImageComponent.Name,
            Checksum = new[]
            {
                new Checksum
                {
                    Algorithm = AlgorithmName.SHA256,
                    ChecksumValue = dockerImageComponent.Digest
                },
            },
            FilesAnalyzed = false,
            Type = "docker"
        };
    }
}
