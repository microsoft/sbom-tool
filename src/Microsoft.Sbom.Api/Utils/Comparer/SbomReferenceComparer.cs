// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils.Comparer;

/// <summary>
/// Compares SBOM references based on their properties.
/// </summary>
public class SbomReferenceComparer : IEqualityComparer<SbomReference>
{
    private static readonly SbomChecksumComparer ChecksumComparer = new SbomChecksumComparer();

    public bool Equals(SbomReference reference1, SbomReference reference2)
    {
        if (reference1 is null && reference2 is null)
        {
            return true;
        }

        if (reference1 is null || reference2 is null)
        {
            return false;
        }

        // ID string comparisons should be case sensitive
        return string.Equals(reference1.ExternalDocumentId, reference2.ExternalDocumentId) &&
                string.Equals(reference1.Document, reference2.Document) &&
                ChecksumComparer.Equals(reference1.Checksum, reference2.Checksum);
    }

    public int GetHashCode(SbomReference obj)
    {
        if (obj is null)
        {
            return 0;
        }

        // Using prime numbers 17 and 31 for hash calculation to reduce collisions.
        var hash = 17;

        hash = (hash * 31) + (obj.ExternalDocumentId?.GetHashCode() ?? 0);
        hash = (hash * 31) + (obj.Document?.GetHashCode() ?? 0);
        hash = (hash * 31) + (obj.Checksum != null ? ChecksumComparer.GetHashCode(obj.Checksum) : 0);

        return hash;
    }
}
