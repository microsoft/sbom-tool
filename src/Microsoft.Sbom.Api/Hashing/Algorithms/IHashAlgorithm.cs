// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

namespace Microsoft.Sbom.Api.Hashing.Algorithms
{
    /// <summary>
    /// Provides a hashing algorithm implementation that can be used
    /// to generate the hash for a given string.
    /// </summary>
    internal interface IHashAlgorithm
    {
        /// <summary>
        /// Returns a byte array of the content using the current hash algorithm.
        /// </summary>
        /// <param name="inputStream">The read stream of the content to be hashed.</param>
        /// <returns>A byte array of the hash value.</returns>
        byte[] ComputeHash(Stream inputStream);
    }
}
