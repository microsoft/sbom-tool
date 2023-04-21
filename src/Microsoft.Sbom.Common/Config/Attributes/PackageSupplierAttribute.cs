// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes;

[AttributeUsage(AttributeTargets.Assembly)]
public class PackageSupplierAttribute : Attribute
{
    public string PackageSupplier { get; set; }

    public PackageSupplierAttribute(string packageSupplier)
    {
        if (string.IsNullOrEmpty(packageSupplier))
        {
            throw new ArgumentException("Package supplier cannot be null or empty.", nameof(packageSupplier));
        }

        PackageSupplier = packageSupplier;
    }
}