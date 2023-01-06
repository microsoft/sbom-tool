// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Provides an API interface to the SBOM generator workflow.
    /// </summary>
    public interface ISBOMGenerator
    {
        ///// <summary>
        ///// Generate an SBOM.
        ///// </summary>
        Task<SBOMGenerationResult> GenerateSBOMAsync();

        /// <summary>
        /// Each SBOM specification requires that each file and package have a specific list of hashes 
        /// generated for them. Use this function to get a list of the required hash algorithms for your 
        /// SBOM specification. The SBOM generator may throw an exception if a hash algorithm value is missing.
        /// </summary>
        /// <param name="specification">The SBOM specification.</param>
        /// <returns>A list of <see cref="HashAlgorithmName"/>.</returns>
        IEnumerable<AlgorithmName> GetRequiredAlgorithms(SBOMSpecification specification);

        /// <summary>
        /// Gets a list of <see cref="SBOMSpecification"/> this SBOM generator supports.
        /// </summary>
        /// <returns>A list of <see cref="SBOMSpecification"/>.</returns>
        IEnumerable<SBOMSpecification> GetSupportedSBOMSpecifications();
    }
}
