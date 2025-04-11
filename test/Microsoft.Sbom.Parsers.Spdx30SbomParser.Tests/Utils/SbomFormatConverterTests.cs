// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Common.Spdx30Entities.Enums;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PackageVerificationCode = Microsoft.Sbom.Common.Spdx30Entities.PackageVerificationCode;

namespace Microsoft.Sbom.Utils;

[TestClass]
public class SbomFormatConverterTests
{
    private File spdxFile;
    private Package spdxPackage;

    [TestInitialize]
    public void SetUp()
    {
        spdxFile = new File
        {
            Name = "testFile.txt",
            CopyrightText = "copyright",
            SpdxId = "SPDXRef-File",
            VerifiedUsing = new List<PackageVerificationCode>
                {
                    new PackageVerificationCode
                    {
                        Algorithm = HashAlgorithm.sha256,
                        HashValue = "abc123"
                    }
                }
        };

        spdxPackage = new Package
        {
            Name = "testPackage",
            PackageVersion = "1.0.0",
            DownloadLocation = "https://example.com",
            CopyrightText = "copyright",
            SpdxId = "SPDXRef-Package",
            VerifiedUsing = new List<PackageVerificationCode>
            {
                new PackageVerificationCode
                {
                    Algorithm = HashAlgorithm.sha256,
                    HashValue = "abc123"
                }
            }
        };
    }

    [TestMethod]
    public void ToSbomFile_SimpleConversion_ReturnsExpectedSbomFile()
    {
        var sbomFile = spdxFile.ToSbomFile();
        AssertSimpleFileConversionSucceeded(sbomFile);
    }

    [TestMethod]
    public void ToSbomFile_WithLicenses_ReturnsExpectedSbomFile()
    {
        var spdx30Elements = AddLicensesToElement(spdxFile);
        var relationships = spdx30Elements.OfType<Relationship>().ToList();
        var sbomFile = spdxFile.ToSbomFile(spdx30Elements, relationships);

        AssertSimpleFileConversionSucceeded(sbomFile);
        Assert.AreEqual(1, sbomFile.LicenseInfoInFiles.Count());
        Assert.AreEqual("MIT", sbomFile.LicenseInfoInFiles.First());
        Assert.AreEqual("CreativeCommons", sbomFile.LicenseConcluded);
    }

    [TestMethod]
    public void ToSbomPackage_SimpleConversion_ReturnsExpectedSbomPackage()
    {
        var sbomPackage = spdxPackage.ToSbomPackage(new List<Element>(), new List<Relationship>());

        AssertSimplePackageConversionSucceeded(sbomPackage);
        Assert.IsNull(sbomPackage.LicenseInfo.Declared);
        Assert.IsNull(sbomPackage.LicenseInfo.Concluded);
        Assert.IsNull(sbomPackage.Supplier);
        Assert.IsNull(sbomPackage.PackageUrl);
    }

    [TestMethod]
    public void ToSbomPackage_WithLicenses_ReturnsExpectedSbomPackage()
    {
        var spdx30Elements = AddLicensesToElement(spdxPackage);
        var relationships = spdx30Elements.OfType<Relationship>().ToList();
        var sbomPackage = spdxPackage.ToSbomPackage(spdx30Elements, relationships);

        AssertSimplePackageConversionSucceeded(sbomPackage);
        Assert.AreEqual("MIT", sbomPackage.LicenseInfo.Declared);
        Assert.AreEqual("CreativeCommons", sbomPackage.LicenseInfo.Concluded);
        Assert.IsNull(sbomPackage.Supplier);
        Assert.IsNull(sbomPackage.PackageUrl);
    }

    [TestMethod]
    public void ToSbomPackage_WithExternalIdentifier_ReturnsExpectedPackageUrl()
    {
        var externalIdentifier = new ExternalIdentifier
        {
            SpdxId = "SPDXRef-ExternalIdentifier",
            Identifier = "pkg:npm/test-package@1.0.0"
        };

        spdxPackage.ExternalIdentifier = new List<string> { externalIdentifier.SpdxId };

        var spdx30Elements = new List<Element>
        {
            spdxPackage,
            externalIdentifier
        };

        var sbomPackage = spdxPackage.ToSbomPackage(spdx30Elements, new List<Relationship>());
        AssertSimplePackageConversionSucceeded(sbomPackage);
        Assert.IsNull(sbomPackage.LicenseInfo.Declared);
        Assert.IsNull(sbomPackage.LicenseInfo.Concluded);
        Assert.IsNull(sbomPackage.Supplier);
        Assert.AreEqual(externalIdentifier.Identifier, sbomPackage.PackageUrl);
    }

    [TestMethod]
    public void ToSbomPackage_WithOrganization_ReturnsExpectedSupplier()
    {
        var organization = new Organization
        {
            SpdxId = "SPDXRef-Organization",
            Name = "Microsoft"
        };

        spdxPackage.SuppliedBy = organization.SpdxId;

        var spdx30Elements = new List<Element>
        {
            spdxPackage,
            organization
        };

        var sbomPackage = spdxPackage.ToSbomPackage(spdx30Elements, new List<Relationship>());

        AssertSimplePackageConversionSucceeded(sbomPackage);
        Assert.IsNull(sbomPackage.LicenseInfo.Declared);
        Assert.IsNull(sbomPackage.LicenseInfo.Concluded);
        Assert.AreEqual(organization.Name, sbomPackage.Supplier);
        Assert.IsNull(sbomPackage.PackageUrl);
    }

    private void AssertSimpleFileConversionSucceeded(SbomFile sbomFile)
    {
        Assert.AreEqual(spdxFile.Name, sbomFile.Path);
        Assert.AreEqual(spdxFile.CopyrightText, sbomFile.FileCopyrightText);
        Assert.AreEqual(spdxFile.SpdxId, sbomFile.Id);
        Assert.AreEqual(1, sbomFile.Checksum.Count());
        Assert.IsTrue(sbomFile.Checksum.First().Algorithm.Name.Equals(
            HashAlgorithm.sha256.ToString(),
            StringComparison.OrdinalIgnoreCase),
            "Hash algorithm names are not equal");
        Assert.AreEqual(spdxFile.VerifiedUsing.First().HashValue, sbomFile.Checksum.First().ChecksumValue);
    }

    private void AssertSimplePackageConversionSucceeded(SbomPackage sbomPackage)
    {
        Assert.AreEqual(spdxPackage.Name, sbomPackage.PackageName);
        Assert.AreEqual(spdxPackage.PackageVersion, sbomPackage.PackageVersion);
        Assert.AreEqual(spdxPackage.DownloadLocation, sbomPackage.PackageSource);
        Assert.AreEqual(spdxPackage.CopyrightText, sbomPackage.CopyrightText);
        Assert.AreEqual(1, sbomPackage.Checksum.Count());
        Assert.IsTrue(sbomPackage.Checksum.First().Algorithm.Name.Equals(
                    HashAlgorithm.sha256.ToString(),
                    StringComparison.OrdinalIgnoreCase),
                    "Hash algorithm names are not equal");
        Assert.AreEqual(spdxPackage.SpdxId, sbomPackage.Id);
    }

    private List<Element> AddLicensesToElement(Element element)
    {
        var license1 = new AnyLicenseInfo
        {
            Name = "MIT",
            SpdxId = "SPDXRef-License1"
        };
        var license2 = new AnyLicenseInfo
        {
            Name = "CreativeCommons",
            SpdxId = "SPDXRef-License2"
        };

        var relationships = new List<Relationship>
        {
            new Relationship
            {
                From = element.SpdxId,
                To = new List<string> { license1.SpdxId },
                RelationshipType = RelationshipType.HAS_DECLARED_LICENSE
            },
            new Relationship
            {
                From = element.SpdxId,
                To = new List<string> { license2.SpdxId },
                RelationshipType = RelationshipType.HAS_CONCLUDED_LICENSE
            }
        };

        var spdx30Elements = new List<Element> { element, license1, license2 };
        spdx30Elements.AddRange(relationships);
        return spdx30Elements;
    }
}
