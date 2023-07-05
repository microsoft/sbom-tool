// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// Represents the property that is needed to generate External Document Reference.
/// </summary>
public class ExternalDocumentReferenceInfo // TODO: Move to Contracts
{
    /// <summary>
    /// Gets or sets the name of the external SBOM document.
    /// </summary>
    public string ExternalDocumentName { get; set; }

    /// <summary>
    /// Gets or sets the document namespace of the external SBOM.
    /// </summary>
    public string DocumentNamespace { get; set; }

    /// <summary>
    /// Gets or sets checksums of the SBOM file. 
    /// </summary>
    public IEnumerable<Checksum> Checksum { get; set; }

    /// <summary>
    /// Gets or sets iD of the root element that external document is describing.
    /// </summary>
    public string DescribedElementID { get; set; }

    /// <summary>
    /// Gets or sets the path of the external SBOM document.
    /// </summary>
    public string Path { get; set; }
}