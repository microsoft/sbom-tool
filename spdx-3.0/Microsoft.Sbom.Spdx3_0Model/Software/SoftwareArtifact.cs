using Microsoft.Sbom.Core;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Licensing;
using Microsoft.Sbom.Spdx3_0.Software.Enums;

namespace Microsoft.Sbom.Software;

public abstract record SoftwareArtifact(List<NamespaceMap>? namespaces,
                                        ExternalMap? imports,
                                        Uri? spdxId,
                                        string? name,
                                        string? summary,
                                        string? description,
                                        string? comment,
                                        CreationInfo? creationInfo,
                                        IntegrityMethod? verifiedUsing,
                                        ExternalReference? externalReference,
                                        ExternalIdentifier? externalIdentifier,
                                        Agent? originatedBy,
                                        Agent? suppliedBy,
                                        DateTime? builtTime,
                                        DateTime? releaseTime,
                                        DateTime? validUntilTime,
                                        string? standard,
                                        Uri? contentIdentifier,
                                        SoftwarePurpose? primaryPurpose,
                                        SoftwarePurpose? additionalPurpose,
                                        LicenseField? concludedLicense,
                                        LicenseField? declaredLicense,
                                        string? copyrightText,
                                        string? attributionText)
    : Artifact(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifier, originatedBy, suppliedBy, builtTime, releaseTime, validUntilTime, standard);
