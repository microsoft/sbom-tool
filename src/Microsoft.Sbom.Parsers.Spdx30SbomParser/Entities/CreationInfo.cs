// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Used to define creation information about the SPDX element.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/CreationInfo/
/// </summary>
public class CreationInfo : Element
{
    public CreationInfo()
    {
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("@id")]
    public string Id { get; set; }

    /// <summary>
    /// Gets or sets a string that specifies the time the SBOM was created on.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("created")]
    public string Created { get; set; }

    /// <summary>
    /// Gets or sets a list of strings that specify metadata about the creators of this SBOM.
    /// This could be a person, organization, software agent, etc. and is represented by the Agent class.
    /// This is not to be confused with tools that are used to perform tasks.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("createdBy")]
    public IEnumerable<string> CreatedBy { get; set; }

    /// <summary>
    /// Gets or sets a list of strings that specify metadata about the tools used to create this SBOM.
    /// A tool is an element of hardware and/or software utilized to carry out a particular function.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("createdUsing")]
    public IEnumerable<string> CreatedUsing { get; set; }

    [JsonRequired]
    [JsonPropertyName("specVersion")]
    public string SpecVersion { get; set; }

    /// <summary>
    /// Make sure that creation info details are not serialized/deserialized when creating a CreationInfo element.
    /// CreationInfoDetails is a property in the base class Element that is inherited by all other classes except for CreationInfo.
    /// </summary>
    [JsonIgnore]
    public new string CreationInfoDetails { get; set; }
}
