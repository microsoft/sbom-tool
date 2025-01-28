// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Represents a SPDX 3.0 Package.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/
/// </summary>
public class Package : Software
{
    public Package()
    {
        Type = "software_Package";
    }

    /// <summary>
    /// Gets or sets the name and optional contact information of the person or organization that built this package.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("suppliedBy")]
    public virtual string SuppliedBy { get; set; }

    [JsonRequired]
    [JsonPropertyName("name")]
    public override string Name { get; set; }
}
