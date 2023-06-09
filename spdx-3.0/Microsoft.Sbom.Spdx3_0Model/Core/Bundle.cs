using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Spdx3_0.Core;
public record Bundle(Uri? spdxId = null,
                     string? name = null,
                     string? summary = null,
                     string? description = null,
                     string? comment = null,
                     CreationInfo? creationInfo = null,
                     IList<IntegrityMethod>? verifiedUsing = null,
                     ExternalReference? externalReference = null,
                     IList<ExternalIdentifier>? externalIdentifiers = null,
                     Element? element = null,
                     Element? rootElement = null,
                     List<NamespaceMap>? namespaces = null,
                     ExternalMap? imports = null,
                     string? context = null)
    : ElementCollection(spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers, element, rootElement, namespaces, imports)
{
    [JsonPropertyOrder(-1)]
    [JsonPropertyName("@type")]
    public string Type { get; } = nameof(Bundle);
}
