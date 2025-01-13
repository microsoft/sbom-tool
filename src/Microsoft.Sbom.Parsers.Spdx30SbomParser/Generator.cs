// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Utils;
using RelationshipType = Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums.RelationshipType;
using SbomEntities = Microsoft.Sbom.Extensions.Entities;
using SHA1 = System.Security.Cryptography.SHA1;
using SpdxEntities = Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser;

/// <summary>
/// Generates SPDX 3.0 format elements which are used to make up the SBOM document.
/// </summary>
public class Generator : IManifestGenerator
{
    private static readonly Dictionary<AlgorithmName, HashAlgorithm> AlgorithmMap = new()
    {
        { AlgorithmName.SHA1, HashAlgorithm.sha1 },
        { AlgorithmName.SHA256, HashAlgorithm.sha256 },
        { AlgorithmName.SHA512, HashAlgorithm.sha512 },
        { AlgorithmName.MD5, HashAlgorithm.md5 }
    };

    public AlgorithmName[] RequiredHashAlgorithms => new[] { AlgorithmName.SHA256, AlgorithmName.SHA1 };

    public string Version { get; set; } = string.Join("-", Constants.SPDXName, Constants.SPDXVersion);

    string IManifestGenerator.FilesArrayHeaderName => throw new NotSupportedException();

    string IManifestGenerator.PackagesArrayHeaderName => throw new NotSupportedException();

    string IManifestGenerator.RelationshipsArrayHeaderName => throw new NotSupportedException();

    string IManifestGenerator.ExternalDocumentRefArrayHeaderName => throw new NotSupportedException();

    private JsonSerializerOptions serializerOptions = new JsonSerializerOptions
    {
        Converters = { new ElementSerializer() },
    };

    /// <summary>
    /// Generates all SPDX elements related to a single file.
    /// </summary>
    /// <param name="fileInfo">SBOM file info that needs to be translated to SPDX elements.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public GenerationResult GenerateJsonDocument(InternalSbomFileInfo fileInfo)
    {
        if (fileInfo is null)
        {
            throw new ArgumentNullException(nameof(fileInfo));
        }

        var spdxFileAndRelationshipElements = ConvertSbomFileToSpdxFileAndRelationships(fileInfo);

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxFileAndRelationshipElements, this.serializerOptions)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = spdxFileAndRelationshipElements.First().SpdxId,
            },
        };
    }

    /// <summary>
    /// Generate all SPDX elements related to a package.
    /// </summary>
    /// <param name="packageInfo">Package info to be translated to SPDX elements.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
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

        var spdxSupplier = new Organization
        {
            Name = packageInfo.Supplier ?? Constants.NoAssertionValue,
        };
        spdxSupplier.AddSpdxId();

        var spdxPackage = new Package
        {
            Name = packageInfo.PackageName,
            PackageVersion = packageInfo.PackageVersion,
            DownloadLocation = packageInfo.PackageSource ?? Constants.NoAssertionValue,
            CopyrightText = packageInfo.CopyrightText ?? Constants.NoAssertionValue,
            SuppliedBy = spdxSupplier.SpdxId,
        };
        var packageId = SPDXExtensions.GetSpdxElementId(packageInfo);
        spdxPackage.AddSpdxId(packageId);

        var spdxRelationshipAndLicensesFromSbomPackage = GetSpdxRelationshipsAndLicensesFromSbomPackage(packageInfo, spdxPackage);

        // Add external identifier based on package url and link it back to the package it's related to by setting spdxPackage.ExternalIdentifier
        ExternalIdentifier spdxExternalIdentifier = null;
        if (packageInfo.PackageUrl != null)
        {
            spdxExternalIdentifier = new ExternalIdentifier
            {
                ExternalIdentifierType = "purl",
                Identifier = packageInfo.PackageUrl
            };
        }

        spdxExternalIdentifier.AddSpdxId();
        spdxPackage.ExternalIdentifier = new List<string> { spdxExternalIdentifier.SpdxId };

        var spdxElementsRelatedToPackageInfo = new List<Element>
        {
            spdxSupplier,
            spdxPackage,
            spdxExternalIdentifier,
        };
        spdxElementsRelatedToPackageInfo.AddRange(spdxRelationshipAndLicensesFromSbomPackage);

        var dependOnId = packageInfo.DependOn;
        if (dependOnId is not null && dependOnId != Constants.RootPackageIdValue)
        {
            dependOnId = SPDXExtensions.GenerateSpdxId(spdxPackage, packageInfo.DependOn);
        }

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxElementsRelatedToPackageInfo, this.serializerOptions)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = spdxPackage.SpdxId,
                DependOn = dependOnId
            }
        };
    }

    /// <summary>
    /// Generate root package SPDX elements.
    /// </summary>
    /// <param name="internalMetadataProvider">Metadata that includes info about root package.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public GenerationResult GenerateRootPackage(IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        var spdxExternalIdentifier = new ExternalIdentifier
        {
            ExternalIdentifierType = "purl",
            Identifier = internalMetadataProvider.GetSwidTagId(),
        };
        spdxExternalIdentifier.AddSpdxId();

        var spdxSupplier = new Organization
        {
            Name = string.Format(Constants.PackageSupplierFormatString, internalMetadataProvider.GetPackageSupplier()),
        };

        // Bare minimum package details.
        var spdxPackage = new Package
        {
            SpdxId = Constants.RootPackageIdValue,
            Name = internalMetadataProvider.GetPackageName(),
            PackageVersion = internalMetadataProvider.GetPackageVersion(),
            ExternalIdentifier = new List<string> { spdxExternalIdentifier.SpdxId },
            DownloadLocation = Constants.NoAssertionValue,
            CopyrightText = Constants.NoAssertionValue,
            VerifiedUsing = new List<PackageVerificationCode> { GetPackageVerificationCode(internalMetadataProvider) },
            SuppliedBy = spdxSupplier.SpdxId,
        };

        // Generate SPDX relationship elements to indicate no assertions are made about licenses for this root package.
        var noAssertionLicense = GenerateLicenseElement(null);

        var spdxRelationshipLicenseDeclaredElement = new SpdxEntities.Relationship
        {
            From = spdxPackage.SpdxId,
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
            To = new List<string> { noAssertionLicense.SpdxId },
        };

        var spdxRelationshipLicenseConcludedElement = new SpdxEntities.Relationship
        {
            From = spdxPackage.SpdxId,
            RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE,
            To = new List<string> { noAssertionLicense.SpdxId },
        };

        spdxSupplier.AddSpdxId();
        spdxPackage.AddSpdxId();
        spdxRelationshipLicenseDeclaredElement.AddSpdxId();
        spdxRelationshipLicenseConcludedElement.AddSpdxId();

        var spdxElementsRelatedToRootPackage = new List<Element>
        {
            spdxExternalIdentifier,
            spdxSupplier,
            spdxPackage,
            noAssertionLicense,
            spdxRelationshipLicenseDeclaredElement,
            spdxRelationshipLicenseConcludedElement,
        };

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxElementsRelatedToRootPackage, this.serializerOptions)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = Constants.RootPackageIdValue,
                DocumentId = Constants.SPDXDocumentIdValue
            }
        };
    }

    /// <summary>
    /// Convert external document reference info to SPDX elements.
    /// </summary>
    /// <param name="externalDocumentReferenceInfo">External document reference info.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="MissingHashValueException"></exception>
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

        var packageVerificationCode = new PackageVerificationCode
        {
            Algorithm = HashAlgorithm.sha1,
            HashValue = checksumValue
        };
        packageVerificationCode.AddSpdxId();

        var spdxExternalMap = new ExternalMap
        {
            VerifiedUsing = new List<PackageVerificationCode>
            {
                packageVerificationCode
            },
            ExternalSpdxId = externalDocumentReferenceInfo.DocumentNamespace,
        };

        spdxExternalMap.AddExternalSpdxId(externalDocumentReferenceInfo.ExternalDocumentName, externalDocumentReferenceInfo.Checksum);
        spdxExternalMap.AddSpdxId();
        var externalDocumentReferenceId = spdxExternalMap.ExternalSpdxId;

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxExternalMap, this.serializerOptions)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = externalDocumentReferenceId
            }
        };
    }

    /// <summary>
    /// Generate SPDX elements related to a relationship.
    /// </summary>
    /// <param name="relationship">Relationship info</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public GenerationResult GenerateJsonDocument(SbomEntities.Relationship relationship)
    {
        if (relationship is null)
        {
            throw new ArgumentNullException(nameof(relationship));
        }

        // If target spdxFileElement in spdxRelationship has external reference ID, we will concatenate it together according to SPDX 2.2 standard.
        // In 3.0 this concatenation is not required, however we will retain this behavior for compatibility with SPDX 2.2.
        var targetElement = !string.IsNullOrEmpty(relationship.TargetElementExternalReferenceId) ?
            $"{relationship.TargetElementExternalReferenceId}:{relationship.TargetElementId}"
            : relationship.TargetElementId;
        var sourceElement = relationship.SourceElementId;

        var spdxRelationship = new SpdxEntities.Relationship
        {
            From = sourceElement,
            RelationshipType = this.GetSPDXRelationshipType(relationship.RelationshipType),
            To = new List<string> { targetElement },
        };
        spdxRelationship.AddSpdxId();

        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxRelationship, this.serializerOptions)),
        };
    }

    /// <summary>
    /// Generate all SPDX elements related to document creation.
    /// </summary>
    /// <param name="internalMetadataProvider">Document metadata</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public GenerationResult GenerateJsonDocument(IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        var generationData = internalMetadataProvider.GetGenerationData(Constants.Spdx30ManifestInfo);

        var sbomToolName = internalMetadataProvider.GetMetadata(MetadataKey.SBOMToolName);
        var sbomToolVersion = internalMetadataProvider.GetMetadata(MetadataKey.SBOMToolVersion);
        var packageName = internalMetadataProvider.GetPackageName();
        var packageVersion = internalMetadataProvider.GetPackageVersion();

        var orgName = internalMetadataProvider.GetPackageSupplier();
        var toolName = sbomToolName + "-" + sbomToolVersion;
        var documentName = string.Format(Constants.SPDXDocumentNameFormatString, packageName, packageVersion);

        var spdxOrganization = new Organization
        {
            Name = orgName,
        };

        var spdxTool = new Tool
        {
            Name = toolName,
        };

        spdxOrganization.AddSpdxId();
        spdxTool.AddSpdxId();

        var spdxCreationInfo = new CreationInfo
        {
            Id = "_:creationinfo",
            SpecVersion = Constants.SPDXVersion,
            Created = internalMetadataProvider.GetGenerationTimestamp(),
            CreatedBy = new List<string> { spdxOrganization.SpdxId },
            CreatedUsing = new List<string> { spdxTool.SpdxId },
        };

        var spdxNamespaceMap = new Dictionary<string, string>();
        spdxNamespaceMap["sbom"] = internalMetadataProvider.GetDocumentNamespace();

        var spdxDataLicense = new AnyLicenseInfo
        {
            Name = Constants.DataLicenceValue,
        };
        spdxDataLicense.AddSpdxId();

        var spdxDocument = new SpdxDocument
        {
            DataLicense = spdxDataLicense.SpdxId,
            NamespaceMap = spdxNamespaceMap,
            SpdxId = Constants.SPDXDocumentIdValue,
            Name = documentName,
            ProfileConformance = new List<ProfileIdentifierType> { ProfileIdentifierType.software, ProfileIdentifierType.core, ProfileIdentifierType.simpleLicensing },
        };

        spdxDocument.AddSpdxId();

        var spdxRelationship = new SpdxEntities.Relationship
        {
            From = spdxDataLicense.SpdxId,
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
            To = new List<string> { spdxDocument.SpdxId },
        };

        spdxCreationInfo.AddSpdxId();
        spdxRelationship.AddSpdxId();

        var spdxElementsRelatedToDocCreation = new List<Element> { spdxOrganization, spdxTool, spdxCreationInfo, spdxDataLicense, spdxDocument, spdxRelationship };
        return new GenerationResult
        {
            Document = JsonDocument.Parse(JsonSerializer.Serialize(spdxElementsRelatedToDocCreation, this.serializerOptions)),
            ResultMetadata = new ResultMetadata
            {
                EntityId = spdxDocument.SpdxId,
            },
        };
    }

    /// <summary>
    /// Use file info to generate file and relationship spdx elements.
    /// </summary>
    /// <param name="fileInfo">SBOM file info that needs to be translated to SPDX elements.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    private List<Element> ConvertSbomFileToSpdxFileAndRelationships(InternalSbomFileInfo fileInfo)
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

        var packageVerificationCodes = new List<PackageVerificationCode>();
        foreach (var checksum in fileInfo.Checksum)
        {
            var packageVerificationCode = new PackageVerificationCode
            {
                Algorithm = AlgorithmMap.GetValueOrDefault(checksum.Algorithm),
                HashValue = checksum.ChecksumValue.ToLowerInvariant(),
            };
            packageVerificationCode.AddSpdxId();
            packageVerificationCodes.Add(packageVerificationCode);
        }

        // Generate SPDX file element
        var spdxFileElement = new SpdxEntities.File
        {
            VerifiedUsing = packageVerificationCodes,
            Name = GeneratorUtils.EnsureRelativePathStartsWithDot(fileInfo.Path),
            CopyrightText = fileInfo.FileCopyrightText ?? Constants.NoAssertionValue,
        };
        var fileId = SPDXExtensions.GetSpdxFileId(fileInfo.Path, fileInfo.Checksum);
        spdxFileElement.AddSpdxId(fileId);

        // Generate SPDX spdxRelationship elements
        var spdxRelationshipsFromSbomFile = GetSpdxRelationshipsFromSbomFile(spdxFileElement, fileInfo);

        // Return all spdx elements related to the file info
        var spdxElementsRelatedToFileInfo = new List<Element> { spdxFileElement };
        spdxElementsRelatedToFileInfo.AddRange(spdxRelationshipsFromSbomFile);

        return spdxElementsRelatedToFileInfo;
    }

    private List<Element> GetSpdxRelationshipsFromSbomFile(Element spdxFileElement, InternalSbomFileInfo fileInfo)
    {
        var spdxRelationshipAndLicenseElementsToAddToSBOM = new List<Element>();

        // Convert licenseConcluded to SPDX license element and add a Relationship element for it
        var licenseConcludedElement = GenerateLicenseElement(fileInfo.LicenseConcluded);
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(licenseConcludedElement);

        var spdxRelationshipLicenseConcludedElement = new SpdxEntities.Relationship
        {
            From = spdxFileElement.SpdxId,
            RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE,
            To = new List<string> { licenseConcludedElement.SpdxId }
        };

        spdxRelationshipLicenseConcludedElement.AddSpdxId();
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(spdxRelationshipLicenseConcludedElement);

        // Convert licenseDeclared to SPDX license elements and add Relationship elements for them
        var toRelationships = new List<string>();
        foreach (var licenseInfoInOneFile in fileInfo.LicenseInfoInFiles)
        {
            var licenseDeclaredElement = GenerateLicenseElement(licenseInfoInOneFile);
            toRelationships.Add(licenseDeclaredElement.SpdxId);
        }

        var spdxRelationshipLicenseDeclaredElement = new SpdxEntities.Relationship
        {
            From = spdxFileElement.SpdxId,
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
            To = toRelationships,
        };

        spdxRelationshipLicenseDeclaredElement.AddSpdxId();
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(spdxRelationshipLicenseDeclaredElement);

        return spdxRelationshipAndLicenseElementsToAddToSBOM;
    }

    private List<Element> GetSpdxRelationshipsAndLicensesFromSbomPackage(SbomPackage packageInfo, Element spdxPackage)
    {
        var spdxRelationshipAndLicenseElementsToAddToSBOM = new List<Element>();

        // Convert licenseConcluded to SPDX spdxFileElement and add a Relationship spdxFileElement for it
        var licenseConcludedElement = GenerateLicenseElement(packageInfo.LicenseInfo?.Concluded);
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(licenseConcludedElement);

        var spdxRelationshipLicenseConcludedElement = new SpdxEntities.Relationship
        {
            From = spdxPackage.SpdxId,
            RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE,
            To = new List<string> { licenseConcludedElement.SpdxId }
        };

        spdxRelationshipLicenseConcludedElement.AddSpdxId();
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(spdxRelationshipLicenseConcludedElement);

        // Convert licenseDeclared to SPDX elements and add a Relationship spdxFileElement for them
        var licenseDeclaredElement = GenerateLicenseElement(packageInfo.LicenseInfo?.Declared);
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(licenseDeclaredElement);

        var spdxRelationshipLicenseDeclaredElement = new Entities.Relationship
        {
            From = spdxPackage.SpdxId,
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
            To = new List<string> { licenseDeclaredElement.SpdxId }
        };

        spdxRelationshipLicenseDeclaredElement.AddSpdxId();
        spdxRelationshipAndLicenseElementsToAddToSBOM.Add(spdxRelationshipLicenseDeclaredElement);

        return spdxRelationshipAndLicenseElementsToAddToSBOM;
    }

    private Element GenerateLicenseElement(string licenseInfo)
    {
        Element licenseElement = null;
        if (licenseInfo == null)
        {
            licenseElement = new NoAssertionElement();
        }
        else
        {
            licenseElement = new AnyLicenseInfo { Name = licenseInfo };
        }

        licenseElement.AddSpdxId();
        return licenseElement;
    }

    /// <summary>
    /// Convert SbomEntities.RelationshipType to SPDX 3.0 RelationshipType.
    /// </summary>
    /// <param name="relationshipType"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    private RelationshipType GetSPDXRelationshipType(SbomEntities.RelationshipType relationshipType)
    {
        switch (relationshipType)
        {
            case SbomEntities.RelationshipType.CONTAINS: return RelationshipType.CONTAINS;
            case SbomEntities.RelationshipType.DEPENDS_ON: return RelationshipType.DEPENDS_ON;
            case SbomEntities.RelationshipType.DESCRIBES: return RelationshipType.DESCRIBES;
            case SbomEntities.RelationshipType.PREREQUISITE_FOR: return RelationshipType.HAS_PREREQUISITE;
            case SbomEntities.RelationshipType.DESCRIBED_BY: return RelationshipType.DESCRIBES;
            case SbomEntities.RelationshipType.PATCH_FOR: return RelationshipType.PATCHED_BY;
            default:
                throw new NotImplementedException($"The spdxRelationship {relationshipType} is currently not " +
                                                  $"mapped to any SPDX 3.0 spdxRelationship type.");
        }
    }

    /// <summary>
    /// Generates the package verification code for a given package using the SPDX 3.0 specification.
    ///
    /// Algorithm defined here https://spdx.github.io/spdx-spec/v2.2.2/package-information/#79-package-verification-code-field.
    /// </summary>
    /// <param name="internalMetadataProvider"></param>
    /// <returns></returns>
    private PackageVerificationCode GetPackageVerificationCode(IInternalMetadataProvider internalMetadataProvider)
    {
        // Get a list of SHA1 checksums
        IList<string> sha1Checksums = new List<string>();
        foreach (var checksumArray in internalMetadataProvider.GetGenerationData(Constants.Spdx30ManifestInfo).Checksums)
        {
            sha1Checksums.Add(checksumArray
                .Where(c => c.Algorithm == AlgorithmName.SHA1)
                .Select(c => c.ChecksumValue)
                .FirstOrDefault());
        }

        var packageChecksumString = string.Join(string.Empty, sha1Checksums.OrderBy(s => s));
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
        var sha1Hasher = SHA1.Create();
#pragma warning restore CA5350
        var hashByteArray = sha1Hasher.ComputeHash(Encoding.Default.GetBytes(packageChecksumString));

        var packageVerificationCode = new PackageVerificationCode
        {
            Algorithm = HashAlgorithm.sha1,
            HashValue = Convert.ToHexString(hashByteArray).Replace("-", string.Empty).ToLowerInvariant(),
        };
        packageVerificationCode.AddSpdxId();
        return packageVerificationCode;
    }

    public ManifestInfo RegisterManifest() => Constants.Spdx30ManifestInfo;

    IDictionary<string, object> IManifestGenerator.GetMetadataDictionary(IInternalMetadataProvider internalMetadataProvider) => throw new NotSupportedException();
}
