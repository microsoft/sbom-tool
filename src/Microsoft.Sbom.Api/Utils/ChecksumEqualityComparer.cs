// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

public class ChecksumEqualityComparer : IEqualityComparer<Checksum>
{
    public bool Equals(Checksum checksum1, Checksum checksum2)
    {
        // Check for nulls
        if (checksum1 == null && checksum2 == null)
        {
            return true;
        }

        if (checksum1 == null || checksum2 == null)
        {
            return false;
        }

        // Compare Algorithm and ChecksumValue
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
