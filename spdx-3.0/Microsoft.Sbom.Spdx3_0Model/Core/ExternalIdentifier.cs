using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record ExternalIdentifier(ExternalIdentifierType? externalIdentifierType, string? identifier, string? comment, Uri? identifierLocator, Uri? issuingAuthority);
