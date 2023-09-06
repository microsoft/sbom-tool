// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;
using SPDXChecksum = Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Checksum;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Provides extension methods to convert a SPDX object to
/// the equivalent internal object as defined in Sbom.Contracts.
/// </summary>
internal static class SPDXToSbomFormatConverterExtensions
{
    /// <summary>
    /// Converts a <see cref="SPDXFile"/> object to a <see cref="SbomFile"/> object.
    /// </summary>
    /// <param name="spdxFile"></param>
    /// <returns></returns>
    internal static SbomFile ToSbomFile(this SPDXFile spdxFile)
    {
        return new SbomFile
        {
            Checksum = spdxFile.FileChecksums?.Select(c => c.ToSbomChecksum()),
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
    internal static SbomPackage ToSbomPackage(this SPDXPackage spdxPackage)
    {
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
    /// Converts a <see cref="SPDXRelationship"/> object to a <see cref="SBOMRelationship"/> object.
    /// </summary>
    /// <param name="spdxRelationship"></param>
    /// <returns></returns>
    internal static SBOMRelationship ToSbomRelationship(this SPDXRelationship spdxRelationship)
    {
        return new SBOMRelationship
        {
            RelationshipType = spdxRelationship.RelationshipType.ToString(),
            TargetElementId = spdxRelationship.TargetElementId,
            SourceElementId = spdxRelationship.SourceElementId,
        };
    }

    /// <summary>
    /// Converts a <see cref="SpdxExternalDocumentReference"/> object to a <see cref="SBOMReference"/> object.
    /// </summary>
    /// <param name="spdxExternalDocumentReference"></param>
    /// <returns></returns>
    internal static SBOMReference ToSbomReference(this SpdxExternalDocumentReference spdxExternalDocumentReference)
    {
        return new SBOMReference
        {
            Checksum = spdxExternalDocumentReference.Checksum.ToSbomChecksum(),
            ExternalDocumentId = spdxExternalDocumentReference.ExternalDocumentId,
            Document = spdxExternalDocumentReference.SpdxDocument,
        };
    }

    /// <summary>
    /// Gets the PURL from a <see cref="ExternalReference"/> object using the Locator property.
    /// </summary>
    /// <param name="externalReference"></param>
    /// <returns></returns>
    internal static string ToPurl(this IList<ExternalReference> externalReference)
    {
        var packageManagerReference = externalReference?.Where(e => e.ReferenceCategory.Replace("_", "-") == "PACKAGE-MANAGER")?.First();
        return packageManagerReference?.Locator;
    }

    /// <summary>
    /// Convert a <see cref="SPDXChecksum"/> object to a <see cref="SbomChecksum"/> object.
    /// </summary>
    /// <param name="spdxChecksums"></param>
    /// <returns></returns>
    internal static SbomChecksum ToSbomChecksum(this SPDXChecksum spdxChecksums)
    {
        return new SbomChecksum
        {
            Algorithm = new Contracts.Enums.AlgorithmName(spdxChecksums.Algorithm, null),
            ChecksumValue = spdxChecksums.ChecksumValue,
        };
    }
}
