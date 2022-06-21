// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="LinuxComponent"/>.
    /// </summary>
    internal static class LinuxComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="LinuxComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this LinuxComponent linuxComponent) => new SBOMPackage
        {
            Id = linuxComponent.Id,
            PackageUrl = linuxComponent.PackageUrl?.ToString(),
            PackageName = linuxComponent.Name,
            PackageVersion = linuxComponent.Version,
            FilesAnalyzed = false,
            Type = "linux"
        };
    }
}
