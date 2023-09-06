// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Entities;

/// <summary>
/// A flag that denotes where the file is located, like on disk or inside an SBOM.
/// </summary>
[Flags]
public enum FileLocation
{
    /// <summary>
    /// File is not present anywhere.
    /// </summary>
    None,

    /// <summary>
    /// File is only present on disk.
    /// </summary>
    OnDisk,

    /// <summary>
    /// File is only present inside a SBOM.
    /// </summary>
    InSbomFile,

    /// <summary>
    /// File is present in both the SBOM and on disk.
    /// </summary>
    All = OnDisk | InSbomFile,
}
