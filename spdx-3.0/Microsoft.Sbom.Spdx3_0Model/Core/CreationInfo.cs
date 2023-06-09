using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record CreationInfo(
                           [property: JsonPropertyOrder(-1)]
                           [property: JsonPropertyName("@id")] 
                           string? spdxId = null,
                           string? specVersion = null,
                           string? comment = null,
                           DateTime? created = null,
                           Agent? createdBy = null,
                           string? createdUsing = null,
                           IList<ProfileIdentifierType>? profile = null,
                           string? dataLicense = null);
