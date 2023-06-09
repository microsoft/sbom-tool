namespace Microsoft.Sbom.Spdx3_0.Core;
public record SpdxDocument(string? name,
                           Uri? spdxId = null,
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
    : Bundle(spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers, element, rootElement, namespaces, imports, context);
