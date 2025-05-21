// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Common.Spdx30Entities;

/// <summary>
/// An ExternalIdentifier is a reference to a resource outside the scope of SPDX-3.0 content
/// that provides a unique key within an established domain that can uniquely identify an Element.
/// This is the equivalent of ExternalRef in SPDX-2.2.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/ExternalIdentifier/
/// </summary>
public class ExternalIdentifier : Element
{
    /// <summary>
    /// Gets or sets type of the external identifier.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("externalIdentifierType")]
    public string ExternalIdentifierType { get; set; }

    [JsonRequired]
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; }

    /// <summary>
    /// Gets or sets a unique string without any spaces that specifies a location where the package specific information
    /// can be located. This will be in the form of a uri.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("identifierLocator")]
    public List<string> IdentifierLocator { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("issuingAuthority")]
    public string IssuingAuthority { get; set; }
}
