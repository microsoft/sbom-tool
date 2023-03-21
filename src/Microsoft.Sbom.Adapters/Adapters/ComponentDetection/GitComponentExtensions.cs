// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="GitComponent"/>.
    /// </summary>
    internal static class GitComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="GitComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this GitComponent gitComponent) => new ()
        {
            Id = gitComponent.Id,
            PackageName = gitComponent.Id,
            PackageUrl = gitComponent.PackageUrl?.ToString(),
            PackageSource = gitComponent.RepositoryUrl?.ToString(),
            Checksum = new[]
            {
                new Checksum
                {
                    Algorithm = AlgorithmName.SHA1,
                    ChecksumValue = gitComponent.CommitHash
                },
            },
            FilesAnalyzed = false,
            Type = "git-package"
        };
    }
}
