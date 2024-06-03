// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Checksum = Microsoft.Sbom.Contracts.Checksum;

namespace SPDX22SBOMParserTest;

[TestClass]
public class SPDXExtensionsTest
{
    private const string PackageUrl = "packageUrl";
    private readonly Regex spdxIdAllowedCharsRegex = new Regex("^[a-zA-Z0-9]*$");

    private SPDXPackage spdxPackage = new SPDXPackage();
    private SbomPackage packageInfo = new SbomPackage();

    [TestInitialize]
    public void Setup()
    {
        spdxPackage = new SPDXPackage
        {
            Name = "packageName",
            VersionInfo = "1.0.0"
        };
        packageInfo = new SbomPackage
        {
            PackageUrl = PackageUrl
        };
    }

    [TestMethod]
    public void AddPackageUrlsTest_Success()
    {
        spdxPackage.AddPackageUrls(packageInfo);
        var externalRef = spdxPackage.ExternalReferences.First();
        Assert.AreEqual(ReferenceCategory.PACKAGE_MANAGER.ToNormalizedString(), externalRef.ReferenceCategory);

        // ExternalRepositoryTypes are deserialized as strings for portability when handling 3P SBOMs,
        // but in the context of this test we expect the value to align with a known enum value. So
        // convert to enum for comparison.
        Enum.TryParse<ExternalRepositoryType>(externalRef.Type, out var refType);
        Assert.AreEqual(ExternalRepositoryType.purl, refType);
        Assert.AreEqual(PackageUrl, externalRef.Locator);
    }

    [TestMethod]
    public void AddPackageUrlsTest_WithNullPackageInfo_Success()
    {
        spdxPackage.AddPackageUrls(null);
        Assert.IsNull(spdxPackage.ExternalReferences);
    }

    [TestMethod]
    public void AddPackageUrlsTest_WithNullPackageUrl_Success()
    {
        packageInfo.PackageUrl = null;
        spdxPackage.AddPackageUrls(packageInfo);
        Assert.IsNull(spdxPackage.ExternalReferences);
    }

    [TestMethod]
    public void AddPackageUrlsTest_WithNonNullExternalRef_Success()
    {
        packageInfo.PackageUrl = null;
        spdxPackage.ExternalReferences = new List<ExternalReference>();
        spdxPackage.AddPackageUrls(packageInfo);
        Assert.AreEqual(0, spdxPackage.ExternalReferences.Count());
    }

    [DataTestMethod]
    [DataRow("pkg:npm/glob@7.1.6", "pkg:npm/glob@7.1.6")]
    [DataRow("https://github.com/actions/virtual-environments", "https://github.com/actions/virtual-environments")]

    public void AddPackageUrlsTest_WithSpecialCharacter_Success(string inputUrl, string expectedUrl)
    {
        spdxPackage = new SPDXPackage();
        spdxPackage.AddPackageUrls(new SbomPackage { PackageUrl = inputUrl });

        var externalRef = spdxPackage.ExternalReferences.First();

        Assert.AreEqual(ReferenceCategory.PACKAGE_MANAGER.ToNormalizedString(), externalRef.ReferenceCategory);

        // ExternalRepositoryTypes are deserialized as strings for portability when handling 3P SBOMs,
        // but in the context of this test we expect the value to align with a known enum value. So
        // convert to enum for comparison.
        Enum.TryParse<ExternalRepositoryType>(externalRef.Type, out var refType);
        Assert.AreEqual(ExternalRepositoryType.purl, refType);
        Assert.AreEqual(expectedUrl, externalRef.Locator);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void AddPackageUrlsTest_WithNullSPDXPackage_Failure()
    {
        spdxPackage = null;
        spdxPackage.AddPackageUrls(packageInfo);
    }

    [TestMethod]
    public void AddExternalReferenceSPDXID()
    {
        var name = "test";
        var hash = "ea70261b02144d5234ae990fa0ca4e0bcd8dc2a9";
        var checksum = new Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = hash };

        var reference = new SpdxExternalDocumentReference();
        var id = reference.AddExternalReferenceSpdxId(name, new Checksum[] { checksum });
        Assert.AreEqual(reference.ExternalDocumentId, id);
        Assert.AreEqual(id, $"DocumentRef-{name}-{hash}");
    }

    [TestMethod]
    public void AddSpdxIdTest_SpdxPackage_Success()
    {
        var spdxIdPrefex = "SPDXRef-Package-";
        spdxPackage.SpdxId = null;

        var spdxId = spdxPackage.AddSpdxId(packageInfo);

        Assert.AreEqual(spdxId, spdxPackage.SpdxId);
        Assert.IsTrue(spdxId.StartsWith(spdxIdPrefex, StringComparison.Ordinal));
        Assert.IsTrue(spdxIdAllowedCharsRegex.IsMatch(spdxId.Split(spdxIdPrefex)[1]));
    }

    [TestMethod]
    public void AddSpdxIdTest_SpdxFile_Success()
    {
        var spdxFile = new SPDXFile { SPDXId = null };
        var fileName = "theFileName.txt";
        var checksums = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = "the-hash-value" } };

        var spdxId = spdxFile.AddSpdxId(fileName, checksums);

        Assert.AreEqual(spdxId, spdxFile.SPDXId);
    }

    [TestMethod]
    public void ReferenceCategoryToNormalizedString_DoesNotContainUnderscore()
    {
        foreach (ReferenceCategory referenceCategory in Enum.GetValues(typeof(ReferenceCategory)))
        {
            var value = referenceCategory.ToNormalizedString();
            Assert.IsFalse(
                value.Contains('_'),
                $"The value {value} of the {nameof(ReferenceCategory)} enum contains an underscore character.");
        }
    }
}
