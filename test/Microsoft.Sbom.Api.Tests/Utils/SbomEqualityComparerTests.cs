// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Utils.Comparer;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Common.Spdx30Entities.Enums;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class SbomEqualityComparerTests
{
    private readonly SbomEqualityComparer comparer;
    private List<SPDXFile> spdx22Files;
    private List<SPDXPackage> spdx22Packages;
    private List<File> spdx30Files;
    private List<Package> spdx30Packages;
    private List<Element> spdx30Elements;
    private List<Relationship> relationships;
    private AnyLicenseInfo differentLicenseInfoElement;

    public SbomEqualityComparerTests()
    {
        comparer = new SbomEqualityComparer("dummyPath1", "dummyPath2");
    }

    [TestInitialize]
    public void SetUp()
    {
        spdx22Files = new List<SPDXFile>
        {
            new SPDXFile
            {
                SPDXId = "FileSpdxId",
                FileName = "/path/to/file1.txt",
                FileChecksums = new List<Checksum>
                {
                    new Checksum
                    {
                        ChecksumValue = "checksumValue",
                        Algorithm = "SHA1",
                    }
                },
                LicenseConcluded = "LicenseConcluded",
                LicenseInfoInFiles = new List<string> { "LicenseInfo" },
            },
        };

        spdx30Files = new List<File>
        {
            new File
            {
                SpdxId = "FileSpdxId",
                Name = "/path/to/file1.txt",
                VerifiedUsing = new List<Common.Spdx30Entities.PackageVerificationCode>
                {
                    new Common.Spdx30Entities.PackageVerificationCode
                    {
                        HashValue = "checksumValue",
                        Algorithm = HashAlgorithm.sha1,
                    }
                },
            }
        };

        spdx22Packages = new List<SPDXPackage>
        {
            new SPDXPackage
            {
                SpdxId = "PackageSpdxId",
                Name = "PackageName",
                VersionInfo = "1.0",
                DownloadLocation = "https://example.com/package",
                CopyrightText = "copyright",
                LicenseConcluded = "LicenseConcluded",
                LicenseDeclared = "LicenseInfo",
                Checksums = new List<Checksum>
                {
                    new Checksum
                    {
                        ChecksumValue = "checksumValue",
                        Algorithm = "SHA1",
                    }
                },
                FilesAnalyzed = true,
                ExternalReferences = new List<ExternalReference>
                {
                    new ExternalReference
                    {
                        ReferenceCategory = "PACKAGE-MANAGER",
                        Locator = "purl-example",
                        Type = "purl",
                    }
                },
                Supplier = "Microsoft"
            }
        };

        var externalIdentifier = new ExternalIdentifier
        {
            Identifier = "purl-example",
            SpdxId = "ExternalIdentifierSpdxId"
        };

        var organization = new Organization
        {
            Name = "Microsoft",
            SpdxId = "OrganizationSpdxId"
        };

        spdx30Packages = new List<Package>
        {
            new Package
            {
                Name = "PackageName",
                SpdxId = "PackageSpdxId",
                PackageVersion = "1.0",
                DownloadLocation = "https://example.com/package",
                CopyrightText = "copyright",
                VerifiedUsing = new List<Common.Spdx30Entities.PackageVerificationCode>
                {
                    new Common.Spdx30Entities.PackageVerificationCode
                    {
                        HashValue = "checksumValue",
                        Algorithm = HashAlgorithm.sha1,
                    }
                },
                ExternalIdentifier = new List<string> { externalIdentifier.SpdxId },
                SuppliedBy = organization.SpdxId,
            }
        };

        var licenseConcludedElement = new AnyLicenseInfo
        {
            SpdxId = "SpdxId-LicenseConcluded",
            Name = "LicenseConcluded",
        };

        var licenseInfoElement = new AnyLicenseInfo
        {
            SpdxId = "SpdxId-LicenseInfo",
            Name = "LicenseInfo",
        };

        differentLicenseInfoElement = new AnyLicenseInfo
        {
            SpdxId = "SpdxId-DifferentLicenseInfo",
            Name = "DifferentLicenseInfo",
        };

        relationships = new List<Relationship>();
        var relationship1 = new Relationship
        {
            From = spdx30Files.First().SpdxId,
            To = new List<string> { licenseConcludedElement.SpdxId },
            RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE,
        };
        var relationship2 = new Relationship
        {
            From = spdx30Files.First().SpdxId,
            To = new List<string> { licenseInfoElement.SpdxId },
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
        };
        var relationship3 = new Relationship
        {
            From = spdx30Packages.First().SpdxId,
            To = new List<string> { licenseConcludedElement.SpdxId },
            RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE,
        };
        var relationship4 = new Relationship
        {
            From = spdx30Packages.First().SpdxId,
            To = new List<string> { licenseInfoElement.SpdxId },
            RelationshipType = RelationshipType.HAS_DECLARED_LICENSE,
        };

        spdx30Elements = [.. spdx30Files, .. spdx30Packages];
        relationships.Add(relationship1);
        relationships.Add(relationship2);
        relationships.Add(relationship3);
        relationships.Add(relationship4);
        spdx30Elements.AddRange(relationships);
        spdx30Elements.Add(licenseConcludedElement);
        spdx30Elements.Add(licenseInfoElement);
        spdx30Elements.Add(differentLicenseInfoElement);
        spdx30Elements.Add(externalIdentifier);
        spdx30Elements.Add(organization);
    }

    [TestMethod]
    public void CheckFiles_MatchingFiles_ReturnsTrue()
    {
        var result = comparer.CheckFiles(spdx22Files, spdx30Files, spdx30Elements, relationships);
        Assert.IsTrue(result, "File contents should be equal");
    }

    [TestMethod]
    public void CheckFiles_FilesWithDifferentSpdx22ChecksumValue_ReturnsFalse()
    {
        spdx22Files.First().FileChecksums[0].ChecksumValue = "differentChecksumValue";
        var result = comparer.CheckFiles(spdx22Files, spdx30Files, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different file checksum values should result in different file contents");
    }

    [TestMethod]
    public void CheckFiles_FilesWithDifferentSpdx30ChecksumValue_ReturnsFalse()
    {
        // Change checksum value of SPDX 3.0 file and add it back to the elements list.
        spdx30Files.First().VerifiedUsing[0].HashValue = "differentChecksumValue";
        spdx30Elements.Remove(spdx30Elements.First(element => element is File));
        spdx30Elements.Add(spdx30Files.FirstOrDefault());

        var result = comparer.CheckFiles(spdx22Files, spdx30Files, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different file checksum values should result in different file contents");
    }

    [TestMethod]
    public void CheckFiles_FilesWithDifferentSpdx22License_ReturnsFalse()
    {
        spdx22Files.First().LicenseConcluded = "differentLicense";
        var result = comparer.CheckFiles(spdx22Files, spdx30Files, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different file checksum values should result in different file contents");
    }

    [TestMethod]
    public void CheckFiles_FilesWithDifferentSpdx30License_ReturnsFalse()
    {
        ChangeLicense("FileSpdxId", RelationshipType.HAS_DECLARED_LICENSE);

        var result = comparer.CheckFiles(spdx22Files, spdx30Files, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different license info should result in different file contents");
    }

    [TestMethod]
    public void CheckPackages_MatchingPackages_ReturnsTrue()
    {
        var result = comparer.CheckPackages(spdx22Packages, spdx30Packages, spdx30Elements, relationships);
        Assert.IsTrue(result, "Package contents should be equal");
    }

    [TestMethod]
    public void CheckPackages_PackagesWithDifferentSpdx22ChecksumValue_ReturnsFalse()
    {
        spdx22Packages.First().Checksums[0].ChecksumValue = "differentChecksumValue";
        var result = comparer.CheckPackages(spdx22Packages, spdx30Packages, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different package checksum values should result in different package contents");
    }

    [TestMethod]
    public void CheckPackages_PackagesWithDifferentSpdx30ChecksumValue_ReturnsFalse()
    {
        spdx30Packages.First().VerifiedUsing[0].HashValue = "differentChecksumValue";
        spdx30Elements.Remove(spdx30Elements.First(element => element is Package));
        spdx30Elements.Add(spdx30Packages.FirstOrDefault());

        var result = comparer.CheckPackages(spdx22Packages, spdx30Packages, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different package checksum values should result in different package contents");
    }

    [TestMethod]
    public void CheckPackages_PackagesWithDifferentSpdx22License_ReturnsFalse()
    {
        spdx22Packages.First().LicenseConcluded = "differentLicense";
        var result = comparer.CheckPackages(spdx22Packages, spdx30Packages, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different package license info should result in different package contents");
    }

    [TestMethod]
    public void CheckPackages_PackagesWithDifferentSpdx30License_ReturnsFalse()
    {
        ChangeLicense("PackageSpdxId", RelationshipType.HAS_CONCLUDED_LICENSE);

        var result = comparer.CheckPackages(spdx22Packages, spdx30Packages, spdx30Elements, relationships);
        Assert.IsFalse(result, "Different license info should result in different package contents");
    }

    [TestMethod]
    public void CheckRelationships_MatchingRelationships_ReturnsTrue()
    {
        var spdx22Relationships = new List<SPDXRelationship>
        {
            new SPDXRelationship
            {
                SourceElementId = "SPDXRef-Source",
                TargetElementId = "SPDXRef-Target",
                RelationshipType = "DESCRIBES"
            }
        };

        var spdx30Relationships = new List<Relationship>
        {
            new Relationship
            {
                From = "SPDXRef-Source",
                To = new List<string> { "SPDXRef-Target" },
                RelationshipType = RelationshipType.DESCRIBES
            }
        };

        var result = comparer.CheckRelationships(spdx22Relationships, spdx30Relationships);
        Assert.IsTrue(result, "Matching relationships should return true.");
    }

    [TestMethod]
    public void CheckRelationships_MatchingRelationships_CaseInsensitiveRelationshipType_ReturnsTrue()
    {
        var spdx22Relationships = new List<SPDXRelationship>
        {
            new SPDXRelationship
            {
                SourceElementId = "SPDXRef-Source",
                TargetElementId = "SPDXRef-Target",
                RelationshipType = "describes"
            }
        };

        var spdx30Relationships = new List<Relationship>
        {
            new Relationship
            {
                From = "SPDXRef-Source",
                To = new List<string> { "SPDXRef-Target" },
                RelationshipType = RelationshipType.DESCRIBES
            }
        };

        var result = comparer.CheckRelationships(spdx22Relationships, spdx30Relationships);
        Assert.IsTrue(result, "Matching relationships should return true.");
    }

    [TestMethod]
    public void CheckRelationships_NonMatchingRelationships_ReturnsFalse()
    {
        var spdx22Relationships = new List<SPDXRelationship>
        {
            new SPDXRelationship
            {
                SourceElementId = "SPDXRef-Source",
                TargetElementId = "SPDXRef-Target",
                RelationshipType = "describes"
            }
        };

        var spdx30Relationships = new List<Relationship>
        {
            new Relationship
            {
                From = "SPDXRef-Source",
                To = new List<string> { "SPDXRef-DifferentTarget" },
                RelationshipType = RelationshipType.DESCRIBES
            }
        };

        var result = comparer.CheckRelationships(spdx22Relationships, spdx30Relationships);
        Assert.IsFalse(result, "Non-matching relationships should return false.");
    }

    [TestMethod]
    public void CheckExternalDocRefs_MatchingExternalDocRefs_ReturnsTrue()
    {
        var spdx22ExternalDocRefs = new List<SpdxExternalDocumentReference>
        {
            new SpdxExternalDocumentReference
            {
                ExternalDocumentId = "SPDX-ExternalRef",
                SpdxDocument = "SPDX-OtherDoc",
            }
        };

        var spdx30ExternalDocRefs = new List<ExternalMap>
        {
            new ExternalMap
            {
                SpdxId = "SPDX-ExternalRef",
                ExternalSpdxId = "SPDX-OtherDoc",
            }
        };

        var result = comparer.CheckExternalDocRefs(spdx22ExternalDocRefs, spdx30ExternalDocRefs);
        Assert.IsTrue(result, "Matching external document references should return true.");
    }

    [TestMethod]
    public void CheckExternalDocRefs_NonMatchingExternalDocRefs_ReturnsFalse()
    {
        var spdx22ExternalDocRefs = new List<SpdxExternalDocumentReference>
        {
            new SpdxExternalDocumentReference
            {
                ExternalDocumentId = "SPDX-ExternalRef",
                SpdxDocument = "SPDX-OtherDoc",
            }
        };

        var spdx30ExternalDocRefs = new List<ExternalMap>
        {
            new ExternalMap
            {
                SpdxId = "SPDX-ExternalRef",
                ExternalSpdxId = "SPDX-vairushf",
            }
        };

        var result = comparer.CheckExternalDocRefs(spdx22ExternalDocRefs, spdx30ExternalDocRefs);
        Assert.IsFalse(result, "Non-matching external document references should return false.");
    }

    [TestMethod]
    public void CheckExternalDocRefs_NonMatchingExternalDocRefs_WithNullChecksum_ReturnsFalse()
    {
        var spdx22ExternalDocRefs = new List<SpdxExternalDocumentReference>
        {
            new SpdxExternalDocumentReference
            {
                ExternalDocumentId = "SPDX-ExternalRef",
                SpdxDocument = "SPDX-OtherDoc",
                Checksum = new Checksum
                {
                    ChecksumValue = "checksumValue",
                    Algorithm = "SHA1",
                }
            }
        };

        var spdx30ExternalDocRefs = new List<ExternalMap>
        {
            new ExternalMap
            {
                SpdxId = "SPDX-ExternalRef",
                ExternalSpdxId = "SPDX-OtherDoc",
            }
        };

        var result = comparer.CheckExternalDocRefs(spdx22ExternalDocRefs, spdx30ExternalDocRefs);
        Assert.IsFalse(result, "Non-matching external document references should return false.");
    }

    private void ChangeLicense(string spdxId, RelationshipType relationshipType)
    {
        var elementToUpdate = spdx30Elements.First(element => element is Relationship &&
        (element as Relationship).From == spdxId &&
        (element as Relationship).RelationshipType == relationshipType);
        (elementToUpdate as Relationship).To = new List<string> { differentLicenseInfoElement.SpdxId };

        var relationshipToUpdate = relationships.First(relationship => relationship.From == spdxId &&
        relationship.RelationshipType == relationshipType);
        relationshipToUpdate.To = new List<string> { differentLicenseInfoElement.SpdxId };
    }
}
