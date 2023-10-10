// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser;

/// <summary>
/// Generates a SPDX 2.2 format SBOM document.
/// </summary>
public class Generator : IManifestGenerator
{
    public AlgorithmName[] RequiredHashAlgorithms => new[] { AlgorithmName.SHA256, AlgorithmName.SHA1 };

    public string Version { get; set; } = string.Join("-", Constants.SPDXName, Constants.SPDXVersion);

    public string FilesArrayHeaderName => Constants.FilesArrayHeaderName;

    public string PackagesArrayHeaderName => Constants.PackagesArrayHeaderName;

    public string RelationshipsArrayHeaderName => Constants.RelationshipsArrayHeaderName;

    public string ExternalDocumentRefArrayHeaderName => Constants.ExternalDocumentRefArrayHeaderName;

    public GenerationResult GenerateJsonDocument(InternalSbomFileInfo fileInfo)
    {
        if (fileInfo is null)
        {
            throw new ArgumentNullException(nameof(fileInfo));
        }

        var spdxFileElement = ConvertSbomFileToSpdxFile(fileInfo);
        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxFileElement)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = spdxFileElement.SPDXId
            }
        };
    }

    private SPDXFile ConvertSbomFileToSpdxFile(InternalSbomFileInfo fileInfo)
    {
        if (fileInfo is null)
        {
            throw new ArgumentNullException(nameof(fileInfo));
        }

        if (fileInfo.Checksum?.Any() == false)
        {
            throw new ArgumentException(nameof(fileInfo.Checksum));
        }

        if (string.IsNullOrWhiteSpace(fileInfo.Path))
        {
            throw new ArgumentException(nameof(fileInfo.Path));
        }

        EnsureRequiredHashesPresent(fileInfo.Checksum.ToArray());

        var spdxFileElement = new SPDXFile
        {
            FileChecksums = fileInfo.Checksum
                .Where(c => RequiredHashAlgorithms.Contains(c.Algorithm))
                .Select(fh => new Entities.Checksum { Algorithm = fh.Algorithm.ToString(), ChecksumValue = fh.ChecksumValue.ToLower() })
                .ToList(),
            FileName = EnsureRelativePathStartsWithDot(fileInfo.Path),
            FileCopyrightText = fileInfo.FileCopyrightText ?? Constants.NoAssertionValue,
            LicenseConcluded = fileInfo.LicenseConcluded ?? Constants.NoAssertionValue,
            LicenseInfoInFiles = fileInfo.LicenseInfoInFiles ?? Constants.NoAssertionListValue,
            FileTypes = fileInfo.FileTypes?.Select(this.GetSPDXFileType).ToList(),
        };

        spdxFileElement.AddSpdxId(fileInfo.Path, fileInfo.Checksum);
        return spdxFileElement;
    }

    // Throws a <see cref="MissingHashValueException"/> if the filehashes are missing
    // any of the required hashes
    private void EnsureRequiredHashesPresent(Contracts.Checksum[] fileHashes)
    {
        foreach (var hashAlgorithmName in from hashAlgorithmName in RequiredHashAlgorithms
                 where !fileHashes.Select(fh => fh.Algorithm).Contains(hashAlgorithmName)
                 select hashAlgorithmName)
        {
            throw new MissingHashValueException($"The hash value for algorithm {hashAlgorithmName} is missing from {nameof(fileHashes)}");
        }
    }

    public ManifestInfo RegisterManifest() => Constants.Spdx22ManifestInfo;

    public IDictionary<string, object> GetMetadataDictionary(IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        var generationData = internalMetadataProvider.GetGenerationData(Constants.Spdx22ManifestInfo);

        var sbomToolName = internalMetadataProvider.GetMetadata(MetadataKey.SBOMToolName);
        var sbomToolVersion = internalMetadataProvider.GetMetadata(MetadataKey.SBOMToolVersion);
        var packageName = internalMetadataProvider.GetPackageName();
        var packageVersion = internalMetadataProvider.GetPackageVersion();
        var documentName = string.Format(Constants.SPDXDocumentNameFormatString, packageName, packageVersion);

        var creationInfo = new CreationInfo
        {
            Created = internalMetadataProvider.GetGenerationTimestamp(),
            Creators = new List<string>
            {
                $"Organization: {internalMetadataProvider.GetPackageSupplier()}",
                $"Tool: {sbomToolName}-{sbomToolVersion}"
            }
        };

        return new Dictionary<string, object>
        {
            { Constants.SPDXVersionHeaderName, Version },
            { Constants.DataLicenseHeaderName, Constants.DataLicenceValue },
            { Constants.SPDXIDHeaderName, Constants.SPDXDocumentIdValue },
            { Constants.DocumentNameHeaderName, documentName },
            { Constants.DocumentNamespaceHeaderName,  internalMetadataProvider.GetDocumentNamespace() },
            { Constants.CreationInfoHeaderName, creationInfo },
            { Constants.DocumentDescribesHeaderName, new string[] { generationData.RootPackageId } }
        };
    }

    public GenerationResult GenerateJsonDocument(SbomPackage packageInfo)
    {
        if (packageInfo is null)
        {
            throw new ArgumentNullException(nameof(packageInfo));
        }

        if (packageInfo.PackageName is null)
        {
            throw new ArgumentNullException(nameof(packageInfo.PackageName));
        }

        var spdxPackage = new SPDXPackage
        {
            Name = packageInfo.PackageName,
            VersionInfo = packageInfo.PackageVersion,
            DownloadLocation = packageInfo.PackageSource ?? Constants.NoAssertionValue,
            CopyrightText = packageInfo.CopyrightText ?? Constants.NoAssertionValue,
            LicenseConcluded = packageInfo.LicenseInfo?.Concluded ?? Constants.NoAssertionValue,
            LicenseDeclared = packageInfo.LicenseInfo?.Declared ?? Constants.NoAssertionValue,
            LicenseInfoFromFiles = packageInfo.FilesAnalyzed ? Constants.NoAssertionListValue : null,
            FilesAnalyzed = packageInfo.FilesAnalyzed,
            Supplier = packageInfo.Supplier ?? Constants.NoAssertionValue
        };

        var packageId = spdxPackage.AddSpdxId(packageInfo);
        spdxPackage.AddPackageUrls(packageInfo);

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxPackage)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = packageId
            }
        };
    }

    private string EnsureRelativePathStartsWithDot(string path)
    {
        if (!path.StartsWith(".", StringComparison.Ordinal))
        {
            return "." + path;
        }

        return path;
    }

    public GenerationResult GenerateRootPackage(
        IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // Bare minimum package details.
        var spdxPackage = new SPDXPackage
        {
            SpdxId = Constants.RootPackageIdValue,
            Name = internalMetadataProvider.GetPackageName(),
            VersionInfo = internalMetadataProvider.GetPackageVersion(),
            ExternalReferences = new List<ExternalReference>
            {
                new ExternalReference
                {
                    ReferenceCategory = ReferenceCategory.PACKAGE_MANAGER.ToNormalizedString(),
                    Type = ExternalRepositoryType.purl,
                    Locator = internalMetadataProvider.GetSwidTagId()
                }
            },
            DownloadLocation = Constants.NoAssertionValue,
            CopyrightText = Constants.NoAssertionValue,
            LicenseConcluded = Constants.NoAssertionValue,
            LicenseDeclared = Constants.NoAssertionValue,
            LicenseInfoFromFiles = Constants.NoAssertionListValue,
            FilesAnalyzed = true,
            PackageVerificationCode = internalMetadataProvider.GetPackageVerificationCode(),
            Supplier = string.Format(Constants.PackageSupplierFormatString, internalMetadataProvider.GetPackageSupplier()),
            HasFiles = internalMetadataProvider.GetPackageFilesList()
        };

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxPackage)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = Constants.RootPackageIdValue,
                DocumentId = Constants.SPDXDocumentIdValue
            }
        };
    }

    public GenerationResult GenerateJsonDocument(Relationship relationship)
    {
        if (relationship is null)
        {
            throw new ArgumentNullException(nameof(relationship));
        }

        // If target element in relationship has external reference ID, we need to concatenate it together according to SPDX 2.2 standard.
        var targetElement = !string.IsNullOrEmpty(relationship.TargetElementExternalReferenceId) ?
            $"{relationship.TargetElementExternalReferenceId}:{relationship.TargetElementId}"
            : relationship.TargetElementId;
        var sourceElement = relationship.SourceElementId;

        var spdxRelationship = new SPDXRelationship
        {
            SourceElementId = sourceElement,
            RelationshipType = GetSPDXRelationshipType(relationship.RelationshipType),
            TargetElementId = targetElement
        };

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxRelationship)),
        };
    }

    private SPDXRelationshipType GetSPDXRelationshipType(RelationshipType relationshipType)
    {
        switch (relationshipType)
        {
            case RelationshipType.CONTAINS: return SPDXRelationshipType.CONTAINS;
            case RelationshipType.DEPENDS_ON: return SPDXRelationshipType.DEPENDS_ON;
            case RelationshipType.DESCRIBES: return SPDXRelationshipType.DESCRIBES;
            case RelationshipType.PREREQUISITE_FOR: return SPDXRelationshipType.PREREQUISITE_FOR;
            case RelationshipType.DESCRIBED_BY: return SPDXRelationshipType.DESCRIBED_BY;
            case RelationshipType.PATCH_FOR: return SPDXRelationshipType.PATCH_FOR;
            default:
                throw new NotImplementedException($"The relationship {relationshipType} is currently not " +
                                                  $"mapped to any SPDX 2.2 relationship type.");
        }
    }

    private SPDXFileType GetSPDXFileType(FileType fileType)
    {
        switch (fileType)
        {
            case FileType.SPDX: return SPDXFileType.SPDX;
            default:
                throw new NotImplementedException($"The fileType {fileType} is currently not " +
                                                  $"mapped to any SPDX 2.2 file type.");
        }
    }

    public GenerationResult GenerateJsonDocument(ExternalDocumentReferenceInfo externalDocumentReferenceInfo)
    {
        if (externalDocumentReferenceInfo is null)
        {
            throw new ArgumentNullException(nameof(externalDocumentReferenceInfo));
        }

        if (externalDocumentReferenceInfo.Checksum is null)
        {
            throw new ArgumentNullException(nameof(externalDocumentReferenceInfo.Checksum));
        }

        var sha1Hash = externalDocumentReferenceInfo.Checksum.FirstOrDefault(h => h.Algorithm == AlgorithmName.SHA1) ??
                       throw new MissingHashValueException(
                           $"The hash value for algorithm {AlgorithmName.SHA1} is missing from {nameof(externalDocumentReferenceInfo)}");

        var checksumValue = sha1Hash.ChecksumValue.ToLower();
        var externalDocumentReferenceElement = new SpdxExternalDocumentReference
        {
            Checksum = new Entities.Checksum
            {
                Algorithm = AlgorithmName.SHA1.ToString(),
                ChecksumValue = checksumValue
            },
            SpdxDocument = externalDocumentReferenceInfo.DocumentNamespace
        };

        externalDocumentReferenceElement.AddExternalReferenceSpdxId(externalDocumentReferenceInfo.ExternalDocumentName, externalDocumentReferenceInfo.Checksum);
        var externalDocumentReferenceId = externalDocumentReferenceElement.ExternalDocumentId;

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(externalDocumentReferenceElement)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = externalDocumentReferenceId
            }
        };
    }
}
