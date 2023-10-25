// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Extensions methods for <see cref="CondaComponent" />.
/// </summary>
internal static class CondaComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="CondaComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="condaComponent">The <see cref="CondaComponent" /> to convert.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this CondaComponent condaComponent) => new()
    {
        Id = condaComponent.Id,
        PackageUrl = condaComponent.PackageUrl?.ToString(),
        PackageName = condaComponent.Name,
        PackageVersion = condaComponent.Version,
        PackageSource = condaComponent.Url,
        Checksum = new List<Checksum>
        {
            new()
            {
                Algorithm = AlgorithmName.MD5, ChecksumValue = condaComponent.MD5,
            },
        },
        FilesAnalyzed = false,
        Type = "conda",
    };
}
