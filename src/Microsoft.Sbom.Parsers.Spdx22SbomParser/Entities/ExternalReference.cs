// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

/// <summary>
/// Defines a reference to an external source of additional information, metadata,
/// enumerations, asset identifiers, or downloadable content believed to be
/// relevant to a Package.
/// </summary>
public class ExternalReference
{
    /// <summary>
    /// Gets or sets the category for the external reference.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("referenceCategory")]
    public string ReferenceCategory { get; set; }

    /// <summary>
    /// Gets or sets type of the external reference. These are definined in an appendix in the SPDX specification.
    /// https://spdx.github.io/spdx-spec/appendix-VI-external-repository-identifiers/.
    /// </summary>
    [JsonPropertyName("referenceType")]
    public ExternalRepositoryType Type { get; set; }

    /// <summary>
    /// Gets or sets a unique string without any spaces that specifies a location where the package specific information
    /// can be located. The locator constraints are defined by the <see cref="Type"/>.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("referenceLocator")]
    public string Locator { get; set; }
}
