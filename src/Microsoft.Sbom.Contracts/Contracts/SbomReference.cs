// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Represents a reference for a differnt SBOM in the current SBOM.
/// </summary>
public class SBOMReference
{
    /// <summary>
    /// Gets or sets the unique identifier that defines the referred SBOM.
    /// </summary>
    public string ExternalDocumentId { get; set; }

    /// <summary>
    /// Gets or sets a unique document id for the referred SBOM.
    /// </summary>
    public string Document { get; set; }

    /// <summary>
    /// Gets or sets checksum values for the external SBOM file.
    /// </summary>
    public Checksum Checksum { get; set; }
}
