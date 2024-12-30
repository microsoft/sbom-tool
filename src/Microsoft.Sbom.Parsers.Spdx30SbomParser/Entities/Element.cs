// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Base domain class from which all other SPDX-3.0 domain classes derive.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Element/
/// </summary>
public abstract class Element
{
    protected Element()
    {
        CreationInfoDetails = "_:creationinfo";
        Type = GetType().Name;
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("comment")]
    public string Comment { get; set; }

    [JsonRequired]
    [JsonPropertyName("creationInfo")]
    public string CreationInfoDetails { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("extension")]
    public List<object> Extension { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("externalIdentifier")]
    public List<string> ExternalIdentifier { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("externalRef")]
    public List<string> ExternalRef { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("name")]
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets unique Identifier for elements in SPDX document.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("spdxId")]
    public string SpdxId { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("summary")]
    public string Summary { get; set; }

    /// <summary>
    /// Gets or sets on how packages were verified.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("verifiedUsing")]
    public List<PackageVerificationCode> VerifiedUsing { get; set; }

    [JsonRequired]
    [JsonPropertyName("type")]
    public string Type { get; set; }
}
