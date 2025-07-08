// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions;

public static class MergeableContentExtensions
{
    public static IEnumerable<SbomPackage> ToMergedPackages(this IEnumerable<MergeableContent> contents)
    {
        if (contents == null)
        {
            throw new ArgumentNullException(nameof(contents));
        }

        return contents.SelectMany(c => c.Packages).Distinct();
    }
}
