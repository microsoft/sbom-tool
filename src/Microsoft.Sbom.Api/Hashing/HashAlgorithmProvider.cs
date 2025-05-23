// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Contracts.Interfaces;

namespace Microsoft.Sbom.Api.Hashing;

using System.Linq;

public class HashAlgorithmProvider : IHashAlgorithmProvider
{
    private readonly Dictionary<string, AlgorithmName> algorithmNameMap;

    public HashAlgorithmProvider(IEnumerable<IAlgorithmNames> algorithmNamesList)
    {
        if (algorithmNamesList is null)
        {
            throw new ArgumentNullException(nameof(algorithmNamesList));
        }

        algorithmNameMap = algorithmNamesList
            .SelectMany(_ => _.GetAlgorithmNames())
            .ToDictionary(_ => _.Name, _ => _, StringComparer.InvariantCultureIgnoreCase);
    }

    [Obsolete("No longer required. Functionality moved to constructor.")]
    public void Init()
    {
    }

    public AlgorithmName Get(string algorithmName)
    {
        if (string.IsNullOrWhiteSpace(algorithmName))
        {
            throw new ArgumentException($"'{nameof(algorithmName)}' cannot be null or whitespace.", nameof(algorithmName));
        }

        if (algorithmNameMap.TryGetValue(algorithmName, out var value))
        {
            return value;
        }

        throw new UnsupportedHashAlgorithmException($"Unsupported hash algorithm {algorithmName}");
    }
}
