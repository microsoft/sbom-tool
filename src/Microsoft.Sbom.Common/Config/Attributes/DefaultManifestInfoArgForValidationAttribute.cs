// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Common.Config.Attributes;

[AttributeUsage(AttributeTargets.Assembly)]
[SuppressMessage("Microsoft.Design", "CA1019:DefineAccessorsForAttributeArguments", Justification = "The properties are exposed via a property bag")]
public sealed class DefaultManifestInfoArgForValidationAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the default value of the ManifestInfo to use in case of validation action
    /// where the user hasn't provided any parameter value.
    /// </summary>
    public ManifestInfo ManifestInfo { get; set; }

    public DefaultManifestInfoArgForValidationAttribute(string name, string version)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
        }

        if (string.IsNullOrEmpty(version))
        {
            throw new ArgumentException($"'{nameof(version)}' cannot be null or empty.", nameof(version));
        }

        ManifestInfo = new ManifestInfo
        {
            Name = name,
            Version = version
        };
    }
}
