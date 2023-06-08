using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record ExternalReference(ExternalReferenceType? externalReferenceType, Uri? locator, MediaType? contentType, string? comment);
