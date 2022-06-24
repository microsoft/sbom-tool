// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Security.Cryptography;

namespace Microsoft.Sbom.Api.Hashing.Algorithms
{
    /// <summary>
    /// The hash algorithm implementation of the <see cref="SHA1"/> hash type.
    /// </summary>
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
    public class Sha1HashAlgorithm : IHashAlgorithm
    {
        public byte[] ComputeHash(Stream stream) => SHA1.Create().ComputeHash(stream);
    }
}
