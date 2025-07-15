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

        // Distinct by SbomPackage.Id
        var distinctPackages = mergeableContents
            .SelectMany(c => c.Packages)
            .GroupBy(p => p.Id)
            .Select(g => g.First());

        var packageDictionary = distinctPackages
            .ToDictionary(p => p.Id, p => p);

        var dependencies = new List<KeyValuePair<string, string>>();
        foreach (var content in mergeableContents)
        {
            dependencies.AddRange(content.Relationships
                .Select(r => new KeyValuePair<string, string>(r.SourceElementId, r.TargetElementId)));
        }

        var uniqueDependencies = dependencies.Distinct();

        var packageCallersDictionary = new Dictionary<string, HashSet<string>>();

        // Build the list of callers for each package.
        foreach (var dependency in uniqueDependencies)
        {
            // Skip the root package reference, which is a special case.
            // TODO: Use the shared constant here!
            if (dependency.Key == "SPDXRef-RootPackage")
            {
                continue;
            }

            if (!packageCallersDictionary.TryGetValue(dependency.Value, out var callers))
            {
                callers = new HashSet<string>();
                packageCallersDictionary.Add(dependency.Value, callers);
            }

            callers.Add(dependency.Key);
        }

        // Save the callers in the list of packages
        foreach (var package in packageDictionary.Values)
        {
            if (packageCallersDictionary.TryGetValue(package.Id, out var callers))
            {
                package.DependOn = callers.ToList();
            }
            else
            {
                package.DependOn = null;
            }
        }

        return packageDictionary.Values;
    }
}
