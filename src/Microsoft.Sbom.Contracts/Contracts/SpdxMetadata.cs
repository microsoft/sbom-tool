// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// The object representation of all the metadata in an SPDX document.
/// Name, SpdxVersion, and SpdxId are required fields.
/// </summary>
public class SpdxMetadata
{
    /// <summary>
    /// The version of the SPDX specification used in this document.
    /// </summary>
    public string SpdxVersion { get; set; }

    /// <summary>
    /// The license of the SPDX document.
    /// </summary>
    public string? DataLicense { get; set; }

    /// <summary>
    /// The name of the SPDX document. Usually the name of the package and version.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// The unique namespace URI of the SPDX document.
    /// </summary>
    public Uri? DocumentNamespace { get; set; }

    /// <summary>
    /// Information about the creation of the SPDX document.
    /// </summary>
    public MetadataCreationInfo? CreationInfo { get; set; }

    /// <summary>
    /// Information about the package this SPDX document represents.
    /// </summary>
    public IEnumerable<string>? DocumentDescribes { get; set; }

    /// <summary>
    /// The id of the spdx document.
    /// </summary>
    public string SpdxId { get; set; }
}
