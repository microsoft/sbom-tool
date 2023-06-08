using Microsoft.Sbom.Core;

namespace Microsoft.Sbom.Spdx3_0.Core;
public record Tool(Uri? spdxId,
                   string? name,
                   string? summary,
                   string? description,
                   string? comment,
                   CreationInfo? creationInfo,
                   IntegrityMethod? verifiedUsing,
                   ExternalReference? externalReference,
                   ExternalIdentifier? externalIdentifier) 
    : Element(spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifier);
