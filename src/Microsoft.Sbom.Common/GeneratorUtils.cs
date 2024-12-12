// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Exceptions;

/// <summary>
/// A class for methods that are used by SPDX generators, regardless of which SPDX version is being used.
/// </summary>
public class GeneratorUtils
{
    // Throws a <see cref="MissingHashValueException"/> if the filehashes are missing
    // any of the required hashes
    public static void EnsureRequiredHashesPresent(Checksum[] fileHashes, AlgorithmName[] requiredHashAlgorithms)
    {
        foreach (var hashAlgorithmName in from hashAlgorithmName in requiredHashAlgorithms
                                          where !fileHashes.Select(fh => fh.Algorithm).Contains(hashAlgorithmName)
                                          select hashAlgorithmName)
        {
            throw new MissingHashValueException($"The hash value for algorithm {hashAlgorithmName} is missing from {nameof(fileHashes)}");
        }
    }

    public static string EnsureRelativePathStartsWithDot(string path)
    {
        if (!path.StartsWith(".", StringComparison.Ordinal))
        {
            return "." + path;
        }

        return path;
    }
}
