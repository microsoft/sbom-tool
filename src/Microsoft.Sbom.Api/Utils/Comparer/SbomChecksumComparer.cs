// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils.Comparer;

/// <summary>
/// Compares SBOM checksums based on their properties.
/// </summary>
public class SbomChecksumComparer : IEqualityComparer<Checksum>
{
    public bool Equals(Checksum checksum1, Checksum checksum2)
    {
        if (checksum1 == null && checksum2 == null)
        {
            return true;
        }

        if (checksum1 == null || checksum2 == null)
        {
            return false;
        }

        // Compare Algorithm and ChecksumValue for equality.
        return string.Equals(checksum1.Algorithm.Name, checksum2.Algorithm.Name, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(checksum1.ChecksumValue, checksum2.ChecksumValue, StringComparison.OrdinalIgnoreCase);
    }

    public int GetHashCode(Checksum obj)
    {
        if (obj == null)
        {
            return 0;
        }

        return obj.ChecksumValue.GetHashCode();
    }
}
