// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes;

/// <summary>
/// Checks if the path specified by the string property is a valid file.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
public sealed class FileExistsAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the action for which this validation should run. Default is all.
    /// </summary>
    public ManifestToolActions ForAction { get; set; }

    public FileExistsAttribute()
    {
        ForAction = ManifestToolActions.All;
    }
}
