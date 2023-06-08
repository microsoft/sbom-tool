namespace Microsoft.Sbom.Spdx3_0.Core;
public record Agent(List<NamespaceMap>? namespaces,
                    ExternalMap? imports,
                    Uri? spdxId,
                    string? name,
                    string? summary,
                    string? description,
                    string? comment,
                    CreationInfo? creationInfo,
                    IList<IntegrityMethod>? verifiedUsing,
                    ExternalReference? externalReference,
                    ExternalIdentifier? externalIdentifier)
    : Element(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifier);