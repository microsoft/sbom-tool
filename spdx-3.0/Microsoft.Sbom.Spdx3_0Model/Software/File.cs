using Microsoft.Sbom.Software;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Spdx3_0.Software;
public record File(Core.Agent? originatedBy,
                   Core.Agent? suppliedBy,
                   DateTime? builtTime,
                   DateTime? releaseTime,
                   DateTime? validUntilTime,
                   string? standard,
                   Uri? contentIdentifier,
                   Enums.SoftwarePurpose? primaryPurpose,
                   Enums.SoftwarePurpose? additionalPurpose,
                   Licensing.LicenseField? concludedLicense,
                   Licensing.LicenseField? declaredLicense,
                   string? copyrightText,
                   string? attributionText,
                   MediaType? contentType)
    : SoftwareArtifact(originatedBy, suppliedBy, builtTime, releaseTime, validUntilTime, standard, contentIdentifier, primaryPurpose, additionalPurpose, concludedLicense, declaredLicense, copyrightText, attributionText);
