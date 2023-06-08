using Microsoft.Sbom.Core;
using Microsoft.Sbom.Spdx3_0.Licensing;
using Microsoft.Sbom.Spdx3_0.Software.Enums;

namespace Microsoft.Sbom.Software;

public abstract record SoftwareArtifact(Spdx3_0.Core.Agent? originatedBy,
                                        Spdx3_0.Core.Agent? suppliedBy,
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
    : Artifact(originatedBy, suppliedBy, builtTime, releaseTime, validUntilTime, standard);
