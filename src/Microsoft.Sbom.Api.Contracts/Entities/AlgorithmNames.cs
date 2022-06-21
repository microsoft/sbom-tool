// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Contracts.Enums;
using Microsoft.Sbom.Api.Contracts.Interfaces;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Contracts.Entities
{
    public class AlgorithmNames : IAlgorithmNames
    {
        public IList<AlgorithmName> GetAlgorithmNames()
        {
            return new List<AlgorithmName>
            {
                AlgorithmName.SHA1,
                AlgorithmName.SHA256,
                AlgorithmName.SHA512,
                AlgorithmName.MD5,
            };
        }
    }
}
