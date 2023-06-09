using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Core;

public record CreationInfo(string? specVersion = null,
                           string? comment = null,
                           DateTime? created = null,
                           Agent? createdBy = null,
                           string? createdUsing = null,
                           IList<ProfileIdentifierType>? profile = null,
                           string? dataLicense = null);
