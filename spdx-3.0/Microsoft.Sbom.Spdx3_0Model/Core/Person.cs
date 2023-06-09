using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Spdx3_0.Core;
public record Person(List<NamespaceMap>? namespaces = null,
                     ExternalMap? imports = null,
                     Uri? spdxId = null,
                     string? name = null,
                     string? summary = null,
                     string? description = null,
                     string? comment = null,
                     CreationInfo? creationInfo = null,
                     IList<IntegrityMethod>? verifiedUsing = null,
                     ExternalReference? externalReference = null,
                     IList<ExternalIdentifier>? externalIdentifiers = null)
    : Agent(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers)
{
    [JsonPropertyOrder(-1)]
    [JsonPropertyName("@type")]
    public string Type { get; } = nameof(Person);
}