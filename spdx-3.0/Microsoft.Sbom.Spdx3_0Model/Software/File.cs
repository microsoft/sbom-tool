using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Core.Enums;
using Microsoft.Sbom.Spdx3_0.Licensing;
using Microsoft.Sbom.Spdx3_0.Software.Enums;

namespace Microsoft.Sbom.Spdx3_0.Software;
public record File(string? name,
                   List<NamespaceMap>? namespaces = null,
                   ExternalMap? imports = null,
                   Uri? spdxId = null,
                   string? summary = null,
                   string? description = null,
                   string? comment = null,
                   CreationInfo? creationInfo = null,
                   IList<IntegrityMethod>? VerifiedUsing = null,
                   ExternalReference? externalReference = null,
                   ExternalIdentifier? externalIdentifier = null,
                   Agent? originatedBy = null,
                   Agent? suppliedBy = null,
                   DateTime? builtTime = null,
                   DateTime? releaseTime = null,
                   DateTime? validUntilTime = null,
                   string? standard = null,
                   Uri? contentIdentifier = null,
                   SoftwarePurpose? primaryPurpose = null,
                   SoftwarePurpose? additionalPurpose = null,
                   LicenseField? concludedLicense = null,
                   LicenseField? declaredLicense = null,
                   string? copyrightText = null,
                   string? attributionText = null,
                   MediaType? contentType = null) 
    : SoftwareArtifact(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, VerifiedUsing, externalReference, externalIdentifier, originatedBy, suppliedBy, builtTime, releaseTime, validUntilTime, standard, contentIdentifier, primaryPurpose, additionalPurpose, concludedLicense, declaredLicense, copyrightText, attributionText)
{
    [JsonPropertyName("@type")]
    public string Type { get; set; } = "File";
}
