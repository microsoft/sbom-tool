// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Common.Spdx30Entities.Enums;

namespace Microsoft.Sbom.Common.Spdx30Entities;

/// <summary>
/// Represents the hash value of the element using the algorithm specified.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/PackageVerificationCode/
/// </summary>
public class PackageVerificationCode : Element
{
    /// <summary>
    /// Gets or sets the algorithm being used to calculate the type of verification.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    [JsonRequired]
    [JsonPropertyName("algorithm")]
    public HashAlgorithm Algorithm { get; set; }

    /// <summary>
    /// Gets or sets the string value of the algorithm being used to calculate the type of verification.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("hashValue")]
    public string HashValue { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("packageVerificationCodeExcludedFile")]
    public List<string> PackageVerificationCodeExcludedFile { get; set; }
}
