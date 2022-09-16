// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System.Collections.Generic;
using System.Linq;
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
    /// Converts a <see cref="SPDXFile"/> object to a <see cref="SBOMFile"/> object.
    /// </summary>
    /// <param name="spdxFile"></param>
    /// <returns></returns>
    internal static SBOMFile ToSbomFile(this SPDXFile spdxFile)
    {
        return new SBOMFile
        {
            Checksum = spdxFile.FileChecksums?.Select(c => c.ToSbomChecksum()),
            FileCopyrightText = spdxFile.FileCopyrightText,
            Id = spdxFile.SPDXId,
            Path = spdxFile.FileName,
            LicenseConcluded = spdxFile.LicenseConcluded,
            LicenseInfoInFiles = spdxFile.LicenseInfoInFiles,
        };
    }

    internal static SBOMPackage ToSbomPackage(this SPDXPackage spdxPackage)
    {
        return new SBOMPackage
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

    internal static SBOMRelationship ToSbomRelationship(this SPDXRelationship spdxRelationship)
    {
        return new SBOMRelationship
        {
            RelationshipType = spdxRelationship.RelationshipType.ToString(),
            TargetElementId = spdxRelationship.TargetElementId,
            SourceElementId = spdxRelationship.SourceElementId,
        };
    }

    internal static SBOMReference ToSbomReference(this SpdxExternalDocumentReference spdxExternalDocumentReference)
    {
        return new SBOMReference
        {
            Checksum = spdxExternalDocumentReference.Checksum.ToSbomChecksum(),
            ExternalDocumentId = spdxExternalDocumentReference.ExternalDocumentId,
            Document = spdxExternalDocumentReference.SpdxDocument,
        };
    }

    internal static string ToPurl(this IList<ExternalReference> externalReference)
    {
        var packageManagerReference = externalReference?.Where(e => e.ReferenceCategory.Replace("_", "-") == "PACKAGE-MANAGER")?.First();
        return packageManagerReference?.Locator;
    }

    internal static SbomChecksum ToSbomChecksum(this SPDXChecksum spdxChecksums)
    {
        return new SbomChecksum
        {
            Algorithm = new Contracts.Enums.AlgorithmName(spdxChecksums.Algorithm, null),
            ChecksumValue = spdxChecksums.ChecksumValue,
        };
    }
}
