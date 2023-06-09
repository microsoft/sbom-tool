using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Core;
public abstract record Artifact(List<NamespaceMap>? namespaces,
                                ExternalMap? imports,
                                Uri? spdxId,
                                string? name,
                                string? summary,
                                string? description,
                                string? comment,
                                CreationInfo? creationInfo,
                                IList<IntegrityMethod>? verifiedUsing,
                                ExternalReference? externalReference,
                                IList<ExternalIdentifier>? externalIdentifiers,
                                Agent? originatedBy,
                                Agent? suppliedBy,
                                DateTime? builtTime,
                                DateTime? releaseTime,
                                DateTime? validUntilTime,
                                string? standard)
    : Element(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers);