// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System.Collections.Generic;
using System.Text.Json.Serialization;

public class Snippet
{
    [JsonPropertyName("SPDXID")]
    public string SPDXID { get; set; }

    [JsonPropertyName("comment")]
    public string Comment { get; set; }

    [JsonPropertyName("copyrightText")]
    public string CopyrightText { get; set; }

    [JsonPropertyName("licenseComments")]
    public string LicenseComments { get; set; }

    [JsonPropertyName("licenseConcluded")]
    public string LicenseConcluded { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("licenseInfoInSnippets")]
    public IEnumerable<string> LicenseInfoInSnippets { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("ranges")]
    public IEnumerable<Range> Ranges { get; set; }

    [JsonPropertyName("snippetFromFile")]
    public string SnippetFromFile { get; set; }
}
