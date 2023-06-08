using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Core;

public abstract record Element(Uri? spdxId,
                               string? name,
                               string? summary,
                               string? description,
                               string? comment,
                               CreationInfo? creationInfo,
                               IntegrityMethod? verifiedUsing,
                               ExternalReference? externalReference,
                               ExternalIdentifier? externalIdentifier);
