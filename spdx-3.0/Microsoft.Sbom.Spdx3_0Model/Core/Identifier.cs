namespace Microsoft.Sbom.Spdx3_0.Core;
public record Identifier(Uri? spdxId,
                         List<NamespaceMap>? namespaces = null,
                         ExternalMap? imports = null,
                         string? name = null,
                         string? summary = null,
                         string? description = null,
                         string? comment = null,
                         CreationInfo? creationInfo = null,
                         IList<IntegrityMethod>? verifiedUsing = null,
                         ExternalReference? externalReference = null,
                         IList<ExternalIdentifier>? externalIdentifiers = null) 
    : Element(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers);
