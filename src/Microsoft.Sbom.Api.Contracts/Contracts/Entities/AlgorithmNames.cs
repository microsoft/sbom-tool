using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Contracts.Interfaces;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts.Contracts.Entities
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
