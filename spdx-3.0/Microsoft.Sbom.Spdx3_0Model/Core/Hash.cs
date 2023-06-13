using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;
public record Hash(HashAlgorithm algorithm, string hashValue, string? comment = null)
    : IntegrityMethod(comment)
{
    [JsonPropertyOrder(-2)]
    [JsonPropertyName("@type")]
    public string Type { get; } = nameof(Hash);
}