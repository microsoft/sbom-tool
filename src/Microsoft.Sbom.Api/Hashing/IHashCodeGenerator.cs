// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Hashing;

public interface IHashCodeGenerator
{
    /// <summary>
    /// Given a file path, returns a list of <see cref="Checksum"/>for the file
    /// for each hash algorithm name provided in <paramref name="hashAlgorithmNames"/>.
    /// </summary>
    /// <param name="filePath">The path of the file.</param>
    /// <param name="hashAlgorithmNames">A list of the hash algorithms for which hashes will be generated.</param>
    /// <returns>A list of <see cref="Checksum"/>.</returns>
    Checksum[] GenerateHashes(string filePath, AlgorithmName[] hashAlgorithmNames);
}
