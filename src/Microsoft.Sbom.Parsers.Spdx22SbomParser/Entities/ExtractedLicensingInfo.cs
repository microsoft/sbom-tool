// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System.Collections.Generic;
using System.Text.Json.Serialization;

public class ExtractedLicensingInfo
{
    [JsonPropertyName("licenseId")]
    public string LicenseId { get; set; }

    [JsonPropertyName("extractedText")]
    public string ExtractedText { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("comment")]
    public string Comment { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("seeAlsos")]
    public IEnumerable<string> SeeAlsos { get; set; }
}
