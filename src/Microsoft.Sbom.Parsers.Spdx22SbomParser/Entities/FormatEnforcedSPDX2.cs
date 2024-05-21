// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System.Collections.Generic;
using System.Text.Json.Serialization;

public class FormatEnforcedSPDX2 : SPDX2RequiredProperties
{
    // These attributes are not required by the SPDX spec, but may be present in
    // SBOMs produced by sbom-tool or 3P SBOMs. We want to (de)serialize them if they are present.
    [JsonPropertyName("comment")]
    public string Comment { get; set; }

    [JsonPropertyName("documentDescribes")]
    public IEnumerable<string> DocumentDescribes { get; set; }

    [JsonPropertyName("files")]
    public IEnumerable<SPDXFile> Files { get; set; }

    [JsonPropertyName("packages")]
    public IEnumerable<SPDXPackage> Packages { get; set; }

    [JsonPropertyName("relationships")]
    public IEnumerable<SPDXRelationship> Relationships { get; set; }

    // These attributes are not required, and not serialized by sbom-tool SBOMs, but may be present
    // if we are operating on a 3P SBOM. If they are there, we want to deserialize them, so that we
    // do not lose any information if we re-serialize later.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("externalDocumentRefs")]
    public IEnumerable<SpdxExternalDocumentReference> ExternalDocumentReferences { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("snippets")]
    public IEnumerable<Snippet> Snippets { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("hasExtractedLicensingInfos")]
    public IEnumerable<ExtractedLicensingInfo> ExtractedLicensingInfos { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("annotations")]
    public IEnumerable<Annotation> Annotations { get; set; }
}
