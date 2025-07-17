// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Utils;
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
    private readonly bool actionIsAggregate;

    public AlgorithmName[] RequiredHashAlgorithms => new[] { AlgorithmName.SHA256, AlgorithmName.SHA1 };

    public string Version { get; set; } = string.Join("-", Constants.SPDXName, Constants.SPDXVersion);

    public string FilesArrayHeaderName => Constants.FilesArrayHeaderName;

    public string PackagesArrayHeaderName => Constants.PackagesArrayHeaderName;

    public string RelationshipsArrayHeaderName => Constants.RelationshipsArrayHeaderName;

    public string ExternalDocumentRefArrayHeaderName => Constants.ExternalDocumentRefArrayHeaderName;

    // This constructor gets called by an internal consumer that does not use IConfiguration.
    // In this repo, we use it in tests to pin the existing behavior via this constructor.
    public Generator()
    {
        actionIsAggregate = false;
    }

    // This constructor gets used by the production code and by at least one test.
    public Generator(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

        actionIsAggregate = configuration.ManifestToolAction == ManifestToolActions.Aggregate;
    }

    public GenerationResult GenerateJsonDocument(InternalSbomFileInfo fileInfo)
    {
        if (fileInfo is null)
        {
            throw new ArgumentNullException(nameof(fileInfo));
        }

        var spdxFileElement = ConvertSbomFileToSpdxFile(fileInfo);
        return new GenerationResult
        {
            Document = JsonSerializer.SerializeToDocument(spdxFileElement),
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

        GeneratorUtils.EnsureRequiredHashesPresent(fileInfo.Checksum.ToArray(), RequiredHashAlgorithms);

        var spdxFileElement = new SPDXFile
        {
            FileChecksums = fileInfo.Checksum
                .Where(c => RequiredHashAlgorithms.Contains(c.Algorithm))
                .Select(fh => new Entities.Checksum { Algorithm = fh.Algorithm.ToString(), ChecksumValue = fh.ChecksumValue.ToLower() })
                .ToList(),
            FileName = GeneratorUtils.EnsureRelativePathStartsWithDot(fileInfo.Path),
            FileCopyrightText = fileInfo.FileCopyrightText ?? Constants.NoAssertionValue,
            LicenseConcluded = fileInfo.LicenseConcluded ?? Constants.NoAssertionValue,
            LicenseInfoInFiles = fileInfo.LicenseInfoInFiles ?? Constants.NoAssertionListValue,
            FileTypes = fileInfo.FileTypes?.Select(this.GetSPDXFileType).ToList(),
        };

        spdxFileElement.AddSpdxId(fileInfo.Path, fileInfo.Checksum);
        return spdxFileElement;
    }

    public ManifestInfo RegisterManifest() => Constants.Spdx22ManifestInfo;

    public IDictionary<string, object> GetMetadataDictionary(IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        var generationData = internalMetadataProvider.GetGenerationData(Constants.Spdx22ManifestInfo);

        var sbomToolName = internalMetadataProvider.GetMetadata(MetadataKey.SbomToolName);
        var sbomToolVersion = internalMetadataProvider.GetMetadata(MetadataKey.SbomToolVersion);
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

        var dependOnIds = (packageInfo.DependOn ?? Enumerable.Empty<string>())
                            .Where(id => id is not null)
                            .Select(id => ShouldWeKeepTheExistingId(id) ? id : CommonSPDXUtils.GenerateSpdxPackageId(id))
                            .ToList();

        return new GenerationResult
        {
            Document = JsonSerializer.SerializeToDocument(spdxPackage),
            ResultMetadata = new ResultMetadata
            {
                EntityId = packageId,
                DependOn = dependOnIds,
            }
        };
    }

    private bool ShouldWeKeepTheExistingId(string spdxId)
    {
        if (actionIsAggregate)
        {
            // If we are aggregating, we keep the existing SPDX ID.
            return true;
        }

        return spdxId.Equals(Constants.RootPackageIdValue, StringComparison.OrdinalIgnoreCase);
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
                    Type = ExternalRepositoryType.purl.ToString(),
                    Locator = internalMetadataProvider.GetSwidTagId()
                }
            },
            DownloadLocation = Constants.NoAssertionValue,
            CopyrightText = Constants.NoAssertionValue,
            LicenseConcluded = Constants.NoAssertionValue,
            LicenseDeclared = Constants.NoAssertionValue,
            LicenseInfoFromFiles = Constants.NoAssertionListValue,
            FilesAnalyzed = true,
            PackageVerificationCode = GetPackageVerificationCode(internalMetadataProvider),
            Supplier = string.Format(Constants.PackageSupplierFormatString, internalMetadataProvider.GetPackageSupplier()),
            HasFiles = internalMetadataProvider.GetPackageFilesList(Constants.Spdx22ManifestInfo)
        };

        return new GenerationResult
        {
            Document = JsonSerializer.SerializeToDocument(spdxPackage),
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
            RelationshipType = GetSPDXRelationshipType(relationship.RelationshipType).ToString(),
            TargetElementId = targetElement
        };

        return new GenerationResult
        {
            Document = JsonSerializer.SerializeToDocument(spdxRelationship),
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
            Document = JsonSerializer.SerializeToDocument(externalDocumentReferenceElement),
            ResultMetadata = new ResultMetadata
            {
                EntityId = externalDocumentReferenceId
            }
        };
    }

    /// <summary>
    /// Generates the package verification code for a given package using the SPDX 2.2 specification.
    ///
    /// Algorithm defined here https://spdx.github.io/spdx-spec/v2.2.2/package-information/#79-package-verification-code-field.
    /// </summary>
    /// <param name="internalMetadataProvider"></param>
    private PackageVerificationCode GetPackageVerificationCode(IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // Get a list of SHA1 checksums
        IList<string> sha1Checksums = new List<string>();
        foreach (var checksumArray in internalMetadataProvider.GetGenerationData(Constants.Spdx22ManifestInfo).Checksums)
        {
            sha1Checksums.Add(checksumArray
                .Where(c => c.Algorithm == AlgorithmName.SHA1)
                .Select(c => c.ChecksumValue)
                .FirstOrDefault());
        }

        var packageChecksumString = string.Concat(sha1Checksums.OrderBy(s => s));
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
        var sha1Hasher = SHA1.Create(); // CodeQL [SM02196] Sha1 is required per the SPDX spec.
#pragma warning restore CA5350
        var hashByteArray = sha1Hasher.ComputeHash(Encoding.Default.GetBytes(packageChecksumString));

        return new PackageVerificationCode
        {
            PackageVerificationCodeValue = BitConverter
                .ToString(hashByteArray)
                .Replace("-", string.Empty)
                .ToLowerInvariant(),
            PackageVerificationCodeExcludedFiles = null // We currently don't ignore any files.
        };
    }

    /// <summary>
    /// Creation info will not be generated in SPDX 2.2 format.
    /// </summary>
    /// <param name="internalMetadataProvider"></param>
    public GenerationResult GenerateJsonDocument(IInternalMetadataProvider internalMetadataProvider)
    {
        return null;
    }
}
