// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;
using SPDXChecksum = Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Checksum;

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
    public static SbomFile ToSbomFile(this SPDXFile spdxFile)
    {
        var checksums = spdxFile.FileChecksums?.Select(c => c.ToSbomChecksum());

        return new SbomFile
        {
            Checksum = checksums,
            FileCopyrightText = spdxFile.FileCopyrightText,
            Id = spdxFile.SPDXId,
            Path = spdxFile.FileName,
            LicenseConcluded = spdxFile.LicenseConcluded,
            LicenseInfoInFiles = spdxFile.LicenseInfoInFiles,
        };
    }

    /// <summary>
    /// Converts a <see cref="SPDXPackage"/> to a <see cref="SbomPackage"/> object.
    /// </summary>
    /// <param name="spdxPackage"></param>
    /// <returns></returns>
    public static SbomPackage ToSbomPackage(this SPDXPackage spdxPackage)
    {
        if (spdxPackage.PackageVerificationCode is not null
            && string.IsNullOrEmpty(spdxPackage.PackageVerificationCode.PackageVerificationCodeValue))
        {
            throw new ParserException("Package verification code was null or empty.");
        }

        return new SbomPackage
        {
            Checksum = spdxPackage.Checksums?.Select(c => c.ToSbomChecksum()),
            CopyrightText = spdxPackage.CopyrightText,
            FilesAnalyzed = spdxPackage.FilesAnalyzed,
            Id = spdxPackage.SpdxId,
            LicenseInfo = new LicenseInfo
            {
                Declared = spdxPackage.LicenseDeclared,
                Concluded = spdxPackage.LicenseConcluded
            },
            PackageName = spdxPackage.Name,
            PackageSource = spdxPackage.DownloadLocation,
            PackageUrl = spdxPackage.ExternalReferences?.ToPurl(),
            PackageVersion = spdxPackage.VersionInfo,
            Supplier = spdxPackage.Supplier,
        };
    }

    /// <summary>
    /// Converts a <see cref="SPDXRelationship"/> object to a <see cref="SbomRelationship"/> object.
    /// </summary>
    /// <param name="spdxRelationship"></param>
    /// <returns></returns>
    public static SbomRelationship ToSbomRelationship(this SPDXRelationship spdxRelationship)
    {
        return new SbomRelationship
        {
            RelationshipType = spdxRelationship.RelationshipType.ToString(),
            TargetElementId = spdxRelationship.TargetElementId,
            SourceElementId = spdxRelationship.SourceElementId,
        };
    }

    /// <summary>
    /// Converts a <see cref="SpdxExternalDocumentReference"/> object to a <see cref="SbomReference"/> object.
    /// </summary>
    /// <param name="spdxExternalDocumentReference"></param>
    /// <returns></returns>
    public static SbomReference ToSbomReference(this SpdxExternalDocumentReference spdxExternalDocumentReference)
    {
        return new SbomReference
        {
            Checksum = spdxExternalDocumentReference.Checksum?.ToSbomChecksum(),
            ExternalDocumentId = spdxExternalDocumentReference.ExternalDocumentId,
            Document = spdxExternalDocumentReference.SpdxDocument,
        };
    }

    public static ExternalDocumentReferenceInfo ToExternalDocumentReferenceInfo(this SpdxExternalDocumentReference externalDocumentReference)
    {
        if (externalDocumentReference is null)
        {
            return null;
        }

        return new ExternalDocumentReferenceInfo
        {
            ExternalDocumentName = externalDocumentReference.ExternalDocumentId,
            Checksum = new List<SbomChecksum> { externalDocumentReference.Checksum?.ToSbomChecksum() },
            DocumentNamespace = externalDocumentReference.SpdxDocument,
        };
    }

    /// <summary>
    /// Gets the PURL from a <see cref="ExternalReference"/> object using the Locator property.
    /// </summary>
    /// <param name="externalReference"></param>
    /// <returns></returns>
    internal static string ToPurl(this IList<ExternalReference> externalReference)
    {
        var packageManagerReference = externalReference?.Where(e => e.ReferenceCategory.Replace("_", "-", System.StringComparison.Ordinal) == "PACKAGE-MANAGER")?.First();
        return packageManagerReference?.Locator;
    }

    /// <summary>
    /// Convert a <see cref="SPDXChecksum"/> object to a <see cref="SbomChecksum"/> object.
    /// </summary>
    /// <param name="spdxChecksum"></param>
    /// <returns></returns>
    internal static SbomChecksum ToSbomChecksum(this SPDXChecksum spdxChecksum)
    {
        if (spdxChecksum is null)
        {
            return null;
        }

        return new SbomChecksum
        {
            Algorithm = new AlgorithmName(spdxChecksum.Algorithm, null),
            ChecksumValue = spdxChecksum.ChecksumValue,
        };
    }
}
