// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Hashing
{
    /// <summary>
    /// Generates a list of <see cref="Checksum"/> for the given file.
    /// </summary>
    public class HashCodeGenerator : IHashCodeGenerator
    {
        private readonly IFileSystemUtils fileSystemUtils;

        public HashCodeGenerator(IFileSystemUtils fileSystemUtils)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        /// <summary>
        /// Given a file path, returns a list of <see cref="Checksum"/>for the file 
        /// for each hash algorithm name provided in <paramref name="hashAlgorithmNames"/>.
        /// </summary>
        /// <param name="filePath">The path of the file.</param>
        /// <param name="hashAlgorithmNames">A list of the hash algorithms for which hashes will be generated.</param>
        /// <returns>A list of <see cref="Checksum"/>.</returns>
        public Checksum[] GenerateHashes(string filePath, AlgorithmName[] hashAlgorithmNames)
        {
            var fileHashes = new Checksum[hashAlgorithmNames.Length];
            int i = 0;

            using var bufferedStream = new BufferedStream(fileSystemUtils.OpenRead(filePath), 1024 * 32);

            foreach (var hashAlgorithmName in hashAlgorithmNames)
            {
                var checksum = hashAlgorithmName.ComputeHash(bufferedStream);

                fileHashes[i++] = new Checksum
                {
                    Algorithm = hashAlgorithmName,

                    // TODO make this be bytes instead of converting to string.
                    ChecksumValue = BitConverter.ToString(checksum).Replace("-", string.Empty)
                };

                // Seek to origin for the next hashing algorithm
                // TODO check if using multiple streams is cheaper than resuing the same stream.
                bufferedStream.Seek(0, SeekOrigin.Begin);
            }

            return fileHashes;
        }
    }
}
