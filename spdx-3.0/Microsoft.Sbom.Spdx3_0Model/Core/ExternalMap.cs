namespace Microsoft.Sbom.Spdx3_0.Core;

public record ExternalMap(Uri? externalId, IntegrityMethod? verifiedUsing, Uri? locationHint, Uri? definingDocument);
