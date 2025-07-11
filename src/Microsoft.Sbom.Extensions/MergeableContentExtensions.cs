// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions;

public static class MergeableContentExtensions
{
    public static IEnumerable<SbomPackage> ToMergedPackages(this IEnumerable<MergeableContent> mergeableContents)
    {
        if (mergeableContents == null)
        {
            throw new ArgumentNullException(nameof(mergeableContents));
        }

        return mergeableContents.SelectMany(c => c.Packages).Distinct();
    }

    public static IEnumerable<KeyValuePair<string, string>> ToMergedDependsOnRelationships(this IEnumerable<MergeableContent> mergeableContents)
    {
        if (mergeableContents == null)
        {
            throw new ArgumentNullException(nameof(mergeableContents));
        }

        var dependencies = new List<KeyValuePair<string, string>>();
        foreach (var content in mergeableContents)
        {
            dependencies.AddRange(content.Relationships
                .Select(r => new KeyValuePair<string, string>(r.SourceElementId, r.TargetElementId)));
        }

        return dependencies.Distinct();
    }
}
