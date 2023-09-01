// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Customer facing structure that represents a file in a SBOM.
/// </summary>
public class SbomFile
{
    /// <summary>
    /// Gets or sets a list of the checksums for the file.
    /// </summary>
    public IEnumerable<Checksum> Checksum { get; set; }

    /// <summary>
    /// Gets or sets copyright holder of the file, as well as any dates present.
    /// </summary>
    public string FileCopyrightText { get; set; }

    /// <summary>
    /// Gets or sets contain the license the file creator has concluded or alternative values.
    /// </summary>
    public string LicenseConcluded { get; set; }

    /// <summary>
    /// Gets or sets contains any license information actually found in the file.
    /// </summary>
    public IEnumerable<string> LicenseInfoInFiles { get; set; }

    /// <summary>
    /// Gets or sets the relative path to the BuildDropPath of the file in the SBOM.
    /// </summary>
    public string Path { get; set; }

    /// <summary>
    /// Gets or sets unique Identifier for the file.
    /// </summary>
    public string Id { get; set; }
}
