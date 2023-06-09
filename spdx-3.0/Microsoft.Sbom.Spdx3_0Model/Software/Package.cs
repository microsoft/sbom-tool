using System.Text.Json.Serialization;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Licensing;
using Microsoft.Sbom.Spdx3_0.Software.Enums;

namespace Microsoft.Sbom.Spdx3_0.Software;

public record Package(string? name,
                        List<NamespaceMap>? namespaces = null,
                        ExternalMap? imports = null,
                        Uri? spdxId = null,
                        string? summary = null,
                        string? description = null,
                        string? comment = null,
                        CreationInfo? creationInfo = null,
                        IList<IntegrityMethod>? verifiedUsing = null,
                        ExternalReference? externalReference = null,
                        IList<ExternalIdentifier>? externalIdentifiers = null,
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
                        string? packageVersion = null,
                        Uri? downloadLocation = null,
                        Uri? packageUrl = null,
                        Uri? homePage = null,
                        string? sourceInfo = null) 
    : SoftwareArtifact(namespaces, imports, spdxId, name, summary, description, comment, creationInfo, verifiedUsing, externalReference, externalIdentifiers, originatedBy, suppliedBy, builtTime, releaseTime, validUntilTime, standard, contentIdentifier, primaryPurpose, additionalPurpose, concludedLicense, declaredLicense, copyrightText, attributionText)
{
    [JsonPropertyOrder(-1)]
    [JsonPropertyName("@type")]
    public string Type { get; } = nameof(Package);
}