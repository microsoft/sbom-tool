// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        // Distinct by SbomPackage.Id
        var distinctPackages = mergeableContents
            .SelectMany(c => c.Packages)
            .GroupBy(p => p.Id)
            .Select(g => g.First());

        Check(distinctPackages);

        var packageDictionary = distinctPackages
            .ToDictionary(p => p.Id, p => p);

        var dependencies = new List<KeyValuePair<string, string>>();
        foreach (var content in mergeableContents)
        {
            dependencies.AddRange(content.Relationships
                .Select(r => new KeyValuePair<string, string>(r.SourceElementId, r.TargetElementId)));
        }

        var uniqueDependencies = dependencies.Distinct();

        foreach (var dependency in uniqueDependencies)
        {
            if (packageDictionary.TryGetValue(dependency.Key, out var sourcePackage) &&
                packageDictionary.TryGetValue(dependency.Value, out var targetPackage))
            {
                if (sourcePackage.DependOn is null)
                {
                    sourcePackage.DependOn = new List<string>();
                }

                sourcePackage.DependOn.Add(targetPackage.Id);
            }
        }

        return packageDictionary.Values;
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

    private static void Check(IEnumerable<SbomPackage> packages)
    {
        var x = new HashSet<string>();

        foreach (var package in packages)
        {
            if (!x.Contains(package.Id))
            {
                x.Add(package.Id);
            }
            else
            {
                Debug.WriteLine($"Duplicate package found: {package.Id}");
            }
        }
    }
}
