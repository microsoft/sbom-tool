// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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

        return relationship1.RelationshipType.ToString().Equals(relationship2.RelationshipType.ToString(), System.StringComparison.OrdinalIgnoreCase) &&
                relationship1.SourceElementId == relationship2.SourceElementId &&
                relationship1.TargetElementId == relationship2.TargetElementId;
    }

    public int GetHashCode(SbomRelationship obj)
    {
        if (obj == null)
        {
            return 0;
        }

        return obj.RelationshipType.ToLowerInvariant().GetHashCode() ^
              obj.SourceElementId.GetHashCode() ^
              obj.TargetElementId.GetHashCode();
    }
}
