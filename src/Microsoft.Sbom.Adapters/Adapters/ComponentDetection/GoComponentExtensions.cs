// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Extensions methods for <see cref="GoComponent" />.
/// </summary>
internal static class GoComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="GoComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="goComponent">The <see cref="GoComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this GoComponent goComponent) => new()
    {
        Id = goComponent.Id,
        PackageUrl = goComponent.PackageUrl?.ToString(),
        PackageName = goComponent.Name,
        PackageVersion = goComponent.Version,
        Checksum = new List<Checksum>
        {
            new()
            {
                Algorithm = AlgorithmName.SHA256, ChecksumValue = goComponent.Hash,
            },
        },
        FilesAnalyzed = false,
        Type = "go",
    };
}
