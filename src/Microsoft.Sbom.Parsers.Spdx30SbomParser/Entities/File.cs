// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Refers to any object that stores content on a computer.
/// The type of content can optionally be provided in the contentType property.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/File/
/// </summary>
public class File : Software
{
    public File()
    {
        Type = "software_File";
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("mediaType")]
    public object MediaType { get; set; }

    [JsonRequired]
    [JsonPropertyName("name")]
    public override string Name { get; set; }
}
