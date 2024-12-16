// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// The SpdxDocument provides a convenient way to express information about collections of SPDX Elements that could potentially be serialized as complete units (e.g., all in-scope SPDX data within a single JSON-LD file).
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/SpdxDocument/
/// </summary>
public class SpdxDocument : Element
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("dataLicense")]
    public string DataLicense { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("import")]
    public List<ExternalMap> Import { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("namespaceMap")]
    public List<NamespaceMap> NamespaceMap { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("element")]
    public List<Element> Element { get; set; }

    [JsonRequired]
    [JsonPropertyName("profileConformance")]
    public List<ProfileIdentifierType> ProfileConformance { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("rootElement")]
    public List<Element> RootElement { get; set; }
}
