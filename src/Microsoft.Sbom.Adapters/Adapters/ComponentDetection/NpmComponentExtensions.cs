// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.Internal;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="NpmComponent"/>.
    /// </summary>
    internal static class NpmComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="NpmComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this NpmComponent npmComponent) => new SBOMPackage
        {
            Id = npmComponent.Id,
            PackageUrl = npmComponent.PackageUrl?.ToString(),
            PackageName = npmComponent.Name,
            PackageVersion = npmComponent.Version,
            Checksum = new List<Checksum>()
                {
                    new Checksum()
                    {
                        ChecksumValue = npmComponent.Hash
                    },
                },
            Supplier = npmComponent.Author?.AsSupplier(),
            FilesAnalyzed = false,
            Type = "npm"
        };

        /// <summary>
        /// Converts the <see cref="NpmAuthor"/> to an SPDX Supplier. 
        /// </summary>
        private static string AsSupplier(this NpmAuthor npmAuthor) => (npmAuthor.Name, npmAuthor.Email) switch
        {
            (string name, string email) => $"Organization: {name} ({email})",
            (string name, _) => $"Organization: {name}"
        };
    }
}
