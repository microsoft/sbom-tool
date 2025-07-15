// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions;

public static class MergeableContentExtensions
{
    /// <summary>
    /// Merges multiple <see cref="MergeableContent"/> instances into a distinct collection of <see cref="SbomPackage"/>
    /// objects, including their transitive dependencies. The root package of each <see cref="MergeableContent"/> instance
    /// is promoted to a top-level dependency in the final collection.
    /// </summary>
    public static IEnumerable<SbomPackage> ToMergedPackages(this IEnumerable<MergeableContent> mergeableContents)
    {
        ArgumentNullException.ThrowIfNull(mergeableContents, nameof(mergeableContents));

        var distinctPackages = mergeableContents.CollectDistinctPackages();

        var distinctDependencies = mergeableContents.CollectDistinctDependencies(distinctPackages);

        var packageCallersDictionary = BuildPackageCallersDictionary(distinctDependencies);

        // Save the callers in the list of packages
        UpdatePackageDependencies(distinctPackages, packageCallersDictionary);

        return distinctPackages;
    }

    /// <summary>
    /// Collect the distinct set of packages from all of the MergeableContent objects. In the future, this code
    /// will also merge the package data, creating a single package that contains the most complete information
    /// that is available to us. For now, it simply returns 1 package (the first we encounter) per unique Id.
    /// </summary>
    private static IEnumerable<SbomPackage> CollectDistinctPackages(this IEnumerable<MergeableContent> mergeableContents)
    {
        return mergeableContents
            .SelectMany(c => c.Packages)
            .GroupBy(p => p.Id)
            .Select(g => g.First());
    }

    /// <summary>
    /// Collect the distinct set of package relationships from all of the MergeableContent objects.
    /// </summary>
    private static IEnumerable<KeyValuePair<string, string>> CollectDistinctDependencies(
        this IEnumerable<MergeableContent> mergeableContents, IEnumerable<SbomPackage> distinctPackages)
    {
        var dependencies = new List<KeyValuePair<string, string>>();
        foreach (var mergeableContent in mergeableContents)
        {
            dependencies.AddRange(mergeableContent.Relationships
                .Select(r => new KeyValuePair<string, string>(r.SourceElementId, r.TargetElementId)));
        }

        return dependencies.Distinct();
    }

    /// <summary>
    /// Create a dictionary that maps each package ID to a set of the package IDs that depend on it.
    /// </summary>
    private static IReadOnlyDictionary<string, ISet<string>> BuildPackageCallersDictionary(IEnumerable<KeyValuePair<string, string>> uniqueDependencies)
    {
        var packageCallersDictionary = new Dictionary<string, ISet<string>>();

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

        return packageCallersDictionary;
    }

    /// <summary>
    /// Apply the dependency mappings from the packageCallersDictionary to the distinctPackages.
    /// </summary>
    private static void UpdatePackageDependencies(IEnumerable<SbomPackage> distinctPackages, IReadOnlyDictionary<string, ISet<string>> packageCallersDictionary)
    {
        foreach (var package in distinctPackages)
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
    }
}
