// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using System.Linq;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="NuGetComponent"/>.
    /// </summary>
    internal static class NuGetComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="NuGetComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this NuGetComponent nuGetComponent) => new SBOMPackage
        {
            Id = nuGetComponent.Id,
            PackageUrl = nuGetComponent.PackageUrl?.ToString(),
            PackageName = nuGetComponent.Name,
            PackageVersion = nuGetComponent.Version,
            Supplier = nuGetComponent.Authors?.Any() == true ? $"Organization: {nuGetComponent.Authors.First()}" : null,
            FilesAnalyzed = false,
            Type = "nuget"
        };
    }
}
