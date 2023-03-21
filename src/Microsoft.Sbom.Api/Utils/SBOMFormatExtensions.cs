// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts;
using System;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Extension methods to convert SBOM format specificaitons from multiple formats.
    /// </summary>
    public static class SBOMFormatExtensions
    {
        /// <summary>
        /// Converts a <see cref="SBOMSpecification"/> to a <see cref="ManifestInfo"/> object.
        /// </summary>
        /// <param name="specification"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static ManifestInfo ToManifestInfo(this SBOMSpecification specification)
        {
            if (specification is null)
            {
                throw new ArgumentNullException(nameof(specification));
            }

            return new ManifestInfo
            {
                Name = specification.Name,
                Version = specification.Version
            };
        }

        /// <summary>
        /// Converts a <see cref="ManifestInfo"/> to a <see cref="SBOMSpecification"/> object.
        /// </summary>
        /// <param name="manifestInfo"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static SBOMSpecification ToSBOMSpecification(this ManifestInfo manifestInfo)
        {
            if (manifestInfo is null)
            {
                throw new ArgumentNullException(nameof(manifestInfo));
            }

            return new SBOMSpecification(manifestInfo.Name, manifestInfo.Version);
        }
    }
}
