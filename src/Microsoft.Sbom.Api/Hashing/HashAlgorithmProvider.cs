// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Contracts.Interfaces;

namespace Microsoft.Sbom.Api.Hashing;

public class HashAlgorithmProvider : IHashAlgorithmProvider
{
    private readonly IEnumerable<IAlgorithmNames> algorithmNamesList;
    private readonly Dictionary<string, AlgorithmName> algorithmNameMap;

    public HashAlgorithmProvider(IEnumerable<IAlgorithmNames> algorithmNamesList)
    {
        this.algorithmNamesList = algorithmNamesList ?? throw new ArgumentNullException(nameof(algorithmNamesList));
        algorithmNameMap = new Dictionary<string, AlgorithmName>();
        Init();
    }

    public void Init()
    {
        foreach (var algorithmNames in algorithmNamesList)
        {
            foreach (var algorithmName in algorithmNames.GetAlgorithmNames())
            {
                algorithmNameMap[algorithmName.Name.ToLowerInvariant()] = algorithmName;
            }
        }
    }

    public AlgorithmName Get(string algorithmName)
    {
        if (string.IsNullOrWhiteSpace(algorithmName))
        {
            throw new ArgumentException($"'{nameof(algorithmName)}' cannot be null or whitespace.", nameof(algorithmName));
        }

        if (algorithmNameMap.TryGetValue(algorithmName.ToLowerInvariant(), out AlgorithmName value))
        {
            return value;
        }

        throw new UnsupportedHashAlgorithmException($"Unsupported hash algorithm {algorithmName}");
    }
}