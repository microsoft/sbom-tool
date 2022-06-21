﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="MavenComponent"/>.
    /// </summary>
    internal static class MavenComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="MavenComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this MavenComponent mavenComponent) => new SBOMPackage
        {
            Id = mavenComponent.Id,
            PackageName = $"{mavenComponent.GroupId}.{mavenComponent.ArtifactId}",
            PackageUrl = mavenComponent.PackageUrl?.ToString(),
            PackageVersion = mavenComponent.Version,
            FilesAnalyzed = false,
            Type = "maven"
        };
    }
}
