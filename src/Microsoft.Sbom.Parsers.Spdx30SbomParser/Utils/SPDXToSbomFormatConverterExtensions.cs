// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Relationship = Microsoft.Sbom.Common.Spdx30Entities.Relationship;
using RelationshipType = Microsoft.Sbom.Common.Spdx30Entities.Enums.RelationshipType;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Provides extension methods to convert a SPDX object to
/// the equivalent internal object as defined in Sbom.Contracts.
/// </summary>
public static class SPDXToSbomFormatConverterExtensions
{
    public static SbomFile ToSbomFile(this File spdxFile, List<Element> spdx30Elements = null, List<Relationship> relationships = null)
    {
        return new SbomFile
        {
            Checksum = spdxFile.VerifiedUsing.ToSbomChecksum(),
            FileCopyrightText = spdxFile.CopyrightText == "NOASSERTION" ? null : spdxFile.CopyrightText,
            Path = spdxFile.Name,
            Id = spdxFile.SpdxId,
            LicenseConcluded = spdx30Elements != null && relationships != null
            ? spdxFile.GetSingleLicense(RelationshipType.HAS_CONCLUDED_LICENSE, spdx30Elements, relationships)
            : null,
            LicenseInfoInFiles = spdx30Elements != null && relationships != null
            ? spdxFile.GetMultipleLicenses(RelationshipType.HAS_DECLARED_LICENSE, spdx30Elements, relationships)
            : null
        };
    }

    public static SbomPackage ToSbomPackage(this Package spdxPackage, List<Element> spdx30Elements, List<Relationship> relationships)
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
                Concluded = spdxPackage.GetSingleLicense(RelationshipType.HAS_CONCLUDED_LICENSE, spdx30Elements, relationships),
                Declared = spdxPackage.GetSingleLicense(RelationshipType.HAS_DECLARED_LICENSE, spdx30Elements, relationships),
            },
            Supplier = spdxPackage.GetSupplier(spdx30Elements),
            PackageUrl = spdxPackage.GetPackageUrl(spdx30Elements),
            FilesAnalyzed = true,
            Id = spdxPackage.SpdxId,
        };

        return sbomPackage;
    }

    public static List<SbomRelationship> ToSbomRelationship(this Relationship spdxRelationship)
    {
        var sbomRelationships = new List<SbomRelationship>();
        foreach (var toElement in spdxRelationship.To)
        {
            sbomRelationships.Add(
            new SbomRelationship
            {
                SourceElementId = spdxRelationship.From,
                RelationshipType = spdxRelationship.RelationshipType.ToString(),
                TargetElementId = toElement,
            });
        }

        return sbomRelationships;
    }

    public static SbomReference ToSbomReference(this ExternalMap externalDocumentReference)
    {
        if (externalDocumentReference is null)
        {
            return null;
        }

        return new SbomReference
        {
            Checksum = externalDocumentReference.VerifiedUsing?.ToSbomChecksum().FirstOrDefault(),
            ExternalDocumentId = externalDocumentReference.SpdxId,
            Document = externalDocumentReference.ExternalSpdxId,
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

    private static List<string> GetMultipleLicenses(this Element element, RelationshipType relationshipType, List<Element> spdx30Elements, List<Relationship> relationships)
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
            var licenseElementsWithMatchingSpdxId = spdx30Elements.Where(element => element.SpdxId == toElementSpdxId);
            if (licenseElementsWithMatchingSpdxId.Count() != 1)
            {
                return null;
            }
            else
            {
                licenseElements.Add(licenseElementsWithMatchingSpdxId.First().Name);
            }
        }

        // If there are no license elements, return null.
        return licenseElements.Count == 0 ? null : licenseElements;
    }

    private static string GetSingleLicense(this Element element, RelationshipType relationshipType, List<Element> spdx30Elements, List<Relationship> relationships)
    {
        var spdxId = element.SpdxId;
        var relationshipsDescribingElement = relationships.Where(relationship => relationship.From == spdxId);

        // Get all relationships that describe license information for the given package.
        var toElements = new List<string>();
        foreach (var relationship in relationshipsDescribingElement)
        {
            if (relationship.RelationshipType.Equals(relationshipType))
            {
                toElements = relationship.To;
            }
        }

        // There should only be 1 relationship element for a given RelationshipType for the given Package.
        if (toElements.Count != 1)
        {
            return null;
        }

        var licenseElements = spdx30Elements.Where(element => element.SpdxId == toElements.First());

        // There should only be 1 matching license element.
        return licenseElements.Count() == 1 ? licenseElements.First().Name : null;
    }

    private static string GetSupplier(this Package spdxPackage, List<Element> spdx30Elements)
    {
        var organizationSpdxId = spdxPackage.SuppliedBy;
        if (organizationSpdxId is null)
        {
            return null;
        }

        var organizationElement = spdx30Elements
            .FirstOrDefault(element => element is Organization && element.SpdxId == organizationSpdxId);
        return organizationElement.Name.Equals("NOASSERTION") ? null : organizationElement.Name;
    }

    private static string GetPackageUrl(this Package spdxPackage, List<Element> spdx30Elements)
    {
        var externalIdentifierSpdxId = spdxPackage.ExternalIdentifier?.FirstOrDefault();
        if (externalIdentifierSpdxId is null)
        {
            return null;
        }

        var externalIdentifier = (ExternalIdentifier)spdx30Elements
            .FirstOrDefault(element => element is ExternalIdentifier && element.SpdxId == externalIdentifierSpdxId);
        return externalIdentifier.Identifier;
    }
}
