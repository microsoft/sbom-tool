// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Security.Cryptography;

namespace Microsoft.Sbom.Api.Hashing.Algorithms;

/// <summary>
/// The hash algorithm implementation of the <see cref="SHA256"/> hash type.
/// </summary>
public class Sha256HashAlgorithm : IHashAlgorithm
{
    public byte[] ComputeHash(Stream stream) => SHA256.Create().ComputeHash(stream);
}
