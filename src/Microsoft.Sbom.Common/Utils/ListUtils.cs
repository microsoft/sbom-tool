// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Utils;

using System;
using System.Collections.Generic;

public static class ListUtils
{
    // RemoveAll only added in .NET 8.0.
    public static void RemoveAll<T>(this IList<T> list, Predicate<T> predicate)
    {
        for (var i = 0; i < list.Count; i++)
        {
            if (predicate(list[i]))
            {
                list.RemoveAt(i--);
            }
        }
    }
}
