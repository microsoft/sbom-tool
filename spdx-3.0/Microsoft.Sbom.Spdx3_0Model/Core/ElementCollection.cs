namespace Microsoft.Sbom.Spdx3_0.Core;
public abstract record ElementCollection(Uri? spdxId,
                                           string? name,
                                           string? summary,
                                           string? description,
                                           string? comment,
                                           CreationInfo? creationInfo,
                                           IList<IntegrityMethod>? verifiedUsing,
                                           ExternalReference? externalReference,
                                           IList<ExternalIdentifier>? externalIdentifiers,
                                           Element? element,
                                           Element? rootElement,
                                           List<NamespaceMap>? namespaces,
                                           ExternalMap? imports)
    : Element(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers);
