using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record CreationInfo(string? specVersion, string? comment, DateTime? created, Agent? createdBy, string? createdUsing, ProfileIdentifierType? profile, string? dataLicense);
