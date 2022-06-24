// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.SPDX22SBOMParser.Entities;
using Microsoft.SPDX22SBOMParser.Entities.Enums;
using Microsoft.SPDX22SBOMParser.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Checksum = Microsoft.Sbom.Contracts.Checksum;

namespace SPDX22SBOMParserTest
{
    [TestClass]
    public class SPDXExtensionsTest
    {
        private const string PackageUrl = "packageUrl";
        private readonly Regex spdxIdAllowedCharsRegex = new Regex("^[a-zA-Z0-9]*$");

        private SPDXPackage spdxPackage = new SPDXPackage();
        private SBOMPackage packageInfo = new SBOMPackage();

        [TestInitialize]
        public void Setup()
        {
            spdxPackage = new SPDXPackage
            {
                Name = "packageName",
                VersionInfo = "1.0.0"
            };
            packageInfo = new SBOMPackage
            {
                PackageUrl = PackageUrl
            };
        }

        [TestMethod]
        public void AddPackageUrlsTest_Success()
        {
            spdxPackage.AddPackageUrls(packageInfo);
            var externalRef = spdxPackage.ExternalReferences.First();
            Assert.AreEqual(ReferenceCategory.PACKAGE_MANAGER, externalRef.ReferenceCategory);
            Assert.AreEqual(ExternalRepositoryType.purl, externalRef.Type);
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
        [DataRow("pkg:npm/glob@7.1.6", "pkg:npm/glob%407.1.6")]
        [DataRow("https://github.com/actions/virtual-environments", "https://github.com/actions/virtual-environments")]

        public void AddPackageUrlsTest_WithEncoding_Success(string inputUrl, string expectedUrl)
        {
            spdxPackage = new SPDXPackage();
            spdxPackage.AddPackageUrls(new SBOMPackage { PackageUrl = inputUrl });

            var externalRef = spdxPackage.ExternalReferences.First();

            Assert.AreEqual(ReferenceCategory.PACKAGE_MANAGER, externalRef.ReferenceCategory);
            Assert.AreEqual(ExternalRepositoryType.purl, externalRef.Type);
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
            var checksum = new Microsoft.Sbom.Contracts.Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = hash };

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
            Assert.IsTrue(spdxId.StartsWith(spdxIdPrefex));
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
    }
}
