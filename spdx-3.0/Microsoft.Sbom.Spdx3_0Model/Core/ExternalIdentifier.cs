using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record ExternalIdentifier(ExternalIdentifierType? externalIdentifierType = null,
                                 string? identifier = null,
                                 string? comment = null,
                                 Uri? identifierLocator = null,
                                 Uri? issuingAuthority = null)
{
    [JsonPropertyOrder(-2)]
    [JsonPropertyName("@type")]
    public string Type { get; } = nameof(ExternalIdentifier);
}
