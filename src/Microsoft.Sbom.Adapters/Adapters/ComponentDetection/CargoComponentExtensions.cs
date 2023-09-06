// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="CargoComponent"/>.
/// </summary>
internal static class CargoComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="CargoComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this CargoComponent cargoComponent) => new()
    {
        Id = cargoComponent.Id,
        PackageUrl = cargoComponent.PackageUrl?.ToString(),
        PackageName = cargoComponent.Name,
        PackageVersion = cargoComponent.Version,
        FilesAnalyzed = false,
        Type = "cargo"
    };
}
