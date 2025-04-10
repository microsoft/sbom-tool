// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using RelationshipType = Microsoft.Sbom.Common.Spdx30Entities.Enums.RelationshipType;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Provides extension methods to convert a SPDX object to
/// the equivalent internal object as defined in Sbom.Contracts.
/// </summary>
public static class SPDXToSbomFormatConverterExtensions
{
    /// <summary>
    /// Converts a <see cref="SPDXFile"/> object to a <see cref="SbomFile"/> object.
    /// </summary>
    /// <param name="spdxFile"></param>
    /// <returns></returns>
    public static SbomFile ToSbomFile(this File spdxFile, List<Element> spdx30Elements, List<Common.Spdx30Entities.Relationship> relationships)
    {
        // Manually setting the last two properties to default values.
        // Note that the SPDX 3.0 HAS_DECLARED_LICENSE relationship type is equivalent to LicenseInfoInFiles internally.
        var sbomFile = new SbomFile
        {
            Checksum = spdxFile.VerifiedUsing.ToSbomChecksum(),
            FileCopyrightText = spdxFile.CopyrightText == "NOASSERTION" ? null : spdxFile.CopyrightText,
            LicenseConcluded = spdxFile.GetLicense(RelationshipType.HAS_CONCLUDED_LICENSE, spdx30Elements, relationships).FirstOrDefault(),
            LicenseInfoInFiles = spdxFile.GetLicense(RelationshipType.HAS_DECLARED_LICENSE, spdx30Elements, relationships),
            Path = spdxFile.Name,
        };

        return sbomFile;
    }

    public static SbomPackage ToSbomPackage(this Package spdxPackage, List<Element> spdx30Elements, List<Common.Spdx30Entities.Relationship> relationships)
    {
        var sbomPackage = new SbomPackage
        {
            PackageName = spdxPackage.Name,
            PackageVersion = spdxPackage.PackageVersion,
            PackageSource = spdxPackage.DownloadLocation == "NOASSERTION" ? null : spdxPackage.DownloadLocation,
            CopyrightText = spdxPackage.CopyrightText == "NOASSERTION" ? null : spdxPackage.CopyrightText,
            Checksum = spdxPackage.VerifiedUsing.ToSbomChecksum(),
            LicenseInfo = new LicenseInfo
            {
                Concluded = spdxPackage.GetLicense(RelationshipType.HAS_CONCLUDED_LICENSE, spdx30Elements, relationships).FirstOrDefault(),
                Declared = spdxPackage.GetLicense(RelationshipType.HAS_DECLARED_LICENSE, spdx30Elements, relationships).FirstOrDefault(),
            },
            Supplier = spdxPackage.GetSupplier(spdx30Elements),
            PackageUrl = spdxPackage.GetPackageUrl(spdx30Elements),
            FilesAnalyzed = false,
        };

        return sbomPackage;
    }

    public static List<SbomRelationship> ToSbomRelationship(this Common.Spdx30Entities.Relationship spdxRelationship)
    {
        var sbomRelationships = new List<SbomRelationship>();
        foreach (var toElement in spdxRelationship.To)
        {
            new SbomRelationship
            {
                SourceElementId = spdxRelationship.From,
                RelationshipType = spdxRelationship.RelationshipType.ToString(),
                TargetElementId = toElement,
            };
        }

        return sbomRelationships;
    }

    public static ExternalDocumentReferenceInfo ToExternalDocumentReferenceInfo(this ExternalMap externalDocumentReference)
    {
        if (externalDocumentReference is null)
        {
            return null;
        }

        return new ExternalDocumentReferenceInfo
        {
            Checksum = externalDocumentReference.VerifiedUsing.ToSbomChecksum(),
            DocumentNamespace = externalDocumentReference.ExternalSpdxId,
        };
    }

    /// <summary>
    /// Convert a list of PackageVerificationCodes to internal Checksums.
    /// </summary>
    /// <returns></returns>
    internal static List<SbomChecksum> ToSbomChecksum(this List<PackageVerificationCode> verificationCodes)
    {
        var internalChecksums = new List<SbomChecksum>();
        if (verificationCodes is null || verificationCodes.Count == 0)
        {
            return internalChecksums;
        }

        foreach (var verificationCode in verificationCodes)
        {
            var internalChecksum = new SbomChecksum
            {
                Algorithm = AlgorithmName.FromString(verificationCode.Algorithm.ToString()),
                ChecksumValue = verificationCode.HashValue,
            };

            internalChecksums.Add(internalChecksum);
        }

        return internalChecksums;
    }

    internal static List<string> GetLicense(this Element element, RelationshipType relationshipType, List<Element> spdx30Elements, List<Common.Spdx30Entities.Relationship> relationships)
    {
        var spdxId = element.SpdxId;
        var relationshipsDescribingElement = relationships.Where(relationship => relationship.From == spdxId);

        var toElements = new List<string>();
        foreach (var relationship in relationshipsDescribingElement)
        {
            if (relationship.RelationshipType.Equals(relationshipType))
            {
                toElements = relationship.To;
            }
        }

        var licenseElements = new List<string>();
        foreach (var toElementSpdxId in toElements)
        {
            var licenseElement = spdx30Elements.FirstOrDefault(element => element.SpdxId == toElementSpdxId);
            if (!licenseElement.Name.Equals("NoAssertion"))
            {
                licenseElements.Add(licenseElement.Name);
            }
        }

        return licenseElements.Count == 0 ? null : licenseElements;
    }

    internal static string GetSupplier(this Package spdxPackage, List<Element> spdx30Elements)
    {
        var organizationSpdxId = spdxPackage.SuppliedBy;
        var organizationElement = spdx30Elements
            .FirstOrDefault(element => element is Organization && element.SpdxId == organizationSpdxId);
        return organizationElement.Name.Equals("NOASSERTION") ? null : organizationElement.Name;
    }

    internal static string GetPackageUrl(this Package spdxPackage, List<Element> spdx30Elements)
    {
        var externalIdentifierSpdxId = spdxPackage.ExternalIdentifier.FirstOrDefault();
        if (externalIdentifierSpdxId is null)
        {
            return null;
        }

        var externalIdentifier = (ExternalIdentifier)spdx30Elements
            .FirstOrDefault(element => element is ExternalIdentifier && element.SpdxId == externalIdentifierSpdxId);
        return externalIdentifier.Identifier;
    }
}
