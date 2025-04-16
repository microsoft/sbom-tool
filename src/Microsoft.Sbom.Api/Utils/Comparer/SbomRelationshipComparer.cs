// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Utils.Comparer;

/// <summary>
/// Compares SBOM relationships based on their properties.
/// </summary>
public class SbomRelationshipComparer : IEqualityComparer<SbomRelationship>
{
    public bool Equals(SbomRelationship relationship1, SbomRelationship relationship2)
    {
        if (relationship1 == null || relationship2 == null)
        {
            return false;
        }

        var equals = relationship1.RelationshipType.ToString().Equals(relationship2.RelationshipType.ToString(), StringComparison.OrdinalIgnoreCase) &&
                relationship1.SourceElementId == relationship2.SourceElementId &&
                relationship1.TargetElementId == relationship2.TargetElementId;

        if (!equals)
        {
            Console.WriteLine($"RelationshipType: {relationship1.RelationshipType} != {relationship2.RelationshipType}");
        }

        return equals;
    }

    public int GetHashCode(SbomRelationship obj)
    {
        if (obj == null)
        {
            return 0;
        }

        var hashCode = obj.RelationshipType?.ToString().ToLowerInvariant().GetHashCode() ?? 0;

        // Use XOR to combine hash codes
        if (obj.SourceElementId != null)
        {
            hashCode ^= obj.SourceElementId.GetHashCode();
        }

        if (obj.TargetElementId != null)
        {
            hashCode ^= obj.TargetElementId.GetHashCode();
        }

        return hashCode;
    }
}
