// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Contracts.Interfaces
{
    /// <summary>
    /// The implemention of this interface should provide a list of hashing algorithms that can be
    /// used to generate or validate file hashes by the sbom tool.
    /// 
    /// You can use this implementation to inject custom hashing algorithms to be used in the SBOM tool.
    /// </summary>
    public interface IAlgorithmNames
    {
        /// <summary>
        /// Returns a list of <see cref="AlgorithmName"/> that this implementation provides. 
        /// </summary>
        /// <returns></returns>
        IList<AlgorithmName> GetAlgorithmNames();
    }
}
