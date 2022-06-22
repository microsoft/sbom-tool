// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Microsoft.Sbom.Contracts.Enums
{
    /// <summary>
    /// A list of the names of the hash algorithms that are supported by this SBOM api.
    /// We map to <see cref="HashAlgorithmName"/> for standard 
    /// hash algorithms.
    /// </summary>
    public class AlgorithmName : IEquatable<AlgorithmName>
    {
        public string Name { get; set; }

        public byte[] ComputeHash(Stream stream) => computeHash(stream);

        private Func<Stream, byte[]> computeHash;

        public AlgorithmName(string name, Func<Stream, byte[]> computeHash)
        {
            Name = name;
            this.computeHash = computeHash;
        }

        public override string ToString()
        {
            return Name ?? string.Empty;
        }

        public override bool Equals(object obj)
        {
            return obj is AlgorithmName name && Equals(name);
        }

        public bool Equals(AlgorithmName other)
        {
            // NOTE: intentionally ordinal and case sensitive, matches CNG.
            return Name == other?.Name;
        }

        public override int GetHashCode()
        {
            return Name == null ? 0 : Name.GetHashCode();
        }

        public static bool operator ==(AlgorithmName left, AlgorithmName right)
        {
            if ((left is null) && (right is null))
            {
                return true;
            }

            return left?.Equals(right) == true;
        }

        public static bool operator !=(AlgorithmName left, AlgorithmName right)
        {
            return !(left == right);
        }

        /// <summary>
        /// Gets equivalent to <see cref="HashAlgorithmName.SHA1"/>.
        /// </summary>
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
        public static AlgorithmName SHA1 => new AlgorithmName(nameof(SHA1), stream => System.Security.Cryptography.SHA1.Create().ComputeHash(stream));
#pragma warning restore CA5350

        /// <summary>
        /// Gets equivalent to <see cref="HashAlgorithmName.SHA256"/>.
        /// </summary>
        public static AlgorithmName SHA256 => new AlgorithmName(nameof(SHA256), stream => System.Security.Cryptography.SHA256.Create().ComputeHash(stream));

        /// <summary>
        /// Gets equivalent to <see cref="HashAlgorithmName.SHA512"/>.
        /// </summary>
        public static AlgorithmName SHA512 => new AlgorithmName(nameof(SHA512), stream => System.Security.Cryptography.SHA512.Create().ComputeHash(stream));

        /// <summary>
        /// Gets equivalent to <see cref="HashAlgorithmName.MD5"/>.
        /// </summary>
        public static AlgorithmName MD5 => new AlgorithmName(nameof(MD5), stream => System.Security.Cryptography.MD5.Create().ComputeHash(stream));
    }
}
