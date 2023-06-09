namespace Microsoft.Sbom.Spdx3_0.Core;
public record Tool(List<NamespaceMap>? namespaces,
                   ExternalMap? imports,
                   Uri? spdxId,
                   string? name,
                   string? summary,
                   string? description,
                   string? comment,
                   CreationInfo? creationInfo,
                   IList<IntegrityMethod>? verifiedUsing,
                   ExternalReference? externalReference,
                   IList<ExternalIdentifier>? externalIdentifiers)
    : Element(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers);
