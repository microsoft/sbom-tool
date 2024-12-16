// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;

/// <summary>
/// Defined hash algorithms: https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/HashAlgorithm/
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
[SuppressMessage(
    "StyleCop.CSharp.NamingRules",
    "SA1300:Element should begin with upper-case letter",
    Justification = "These are enum types that are case sensitive and defined by external code.")]
public enum HashAlgorithm
{
    adler32,
    blake2b256,
    blake2b384,
    blake2b512,
    blake3,
    crystalsDilithium,
    crystalsKyber,
    falcon,
    md2,
    md4,
    md5,
    md6,
    other,
    sha1,
    sha224,
    sha256,
    sha384,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    sha512
}
