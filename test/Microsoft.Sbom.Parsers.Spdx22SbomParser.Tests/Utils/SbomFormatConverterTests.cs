// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils.Tests;

[TestClass]
public class SbomFormatConverterTests
{
    [TestMethod]
    public void ToSbomPackage_HappyPath()
    {
        var spdxPackage = new SPDXPackage
        {
            Name = "name",
            SpdxId = "spdxId",
            LicenseConcluded = "licenseConcluded",
            LicenseDeclared = "licenseDeclared",
            CopyrightText = "copyright",
            Supplier = "supplier",
        };

        var sbomPackage = spdxPackage.ToSbomPackage();

        Assert.IsNotNull(sbomPackage);
        Assert.AreEqual(spdxPackage.Name, sbomPackage.PackageName);
        Assert.AreEqual(spdxPackage.SpdxId, sbomPackage.Id);
    }

    [TestMethod]
    public void ToSbomPackage_AcceptsEmptyLicenseInfo()
    {
        var spdxPackage = new SPDXPackage
        {
            Name = "name",
            SpdxId = "spdxId",
            LicenseConcluded = "licenseConcluded",
            LicenseDeclared = "licenseDeclared",
            CopyrightText = "copyright",
            Supplier = "supplier",
            FilesAnalyzed = true,
            LicenseInfoFromFiles = new List<string>(),
        };

        var sbomPackage = spdxPackage.ToSbomPackage();

        Assert.IsNotNull(sbomPackage);
    }

    [TestMethod]
    public void ToExternalDocumentReferenceInfo_HappyPath()
    {
        var spdxExternalDocumentReference = new SpdxExternalDocumentReference
        {
            ExternalDocumentId = "ExternalDocId",
            SpdxDocument = "https://example.com/spdx-document",
            Checksum = new Checksum
            {
                ChecksumValue = "checksumValue",
                Algorithm = "SHA256"
            }
        };

        var externalDocumentReferenceInfo = spdxExternalDocumentReference.ToExternalDocumentReferenceInfo();

        Assert.IsNotNull(externalDocumentReferenceInfo);
        Assert.AreEqual(spdxExternalDocumentReference.ExternalDocumentId, externalDocumentReferenceInfo.ExternalDocumentName);
        Assert.AreEqual(spdxExternalDocumentReference.SpdxDocument, externalDocumentReferenceInfo.DocumentNamespace);
        Assert.IsNotNull(externalDocumentReferenceInfo.Checksum);
        Assert.AreEqual(spdxExternalDocumentReference.Checksum.ChecksumValue, externalDocumentReferenceInfo.Checksum.First().ChecksumValue);
        Assert.AreEqual(spdxExternalDocumentReference.Checksum.Algorithm, externalDocumentReferenceInfo.Checksum.First().Algorithm.ToString());
    }

    [TestMethod]
    public void ToExternalDocumentReferenceInfo_NullChecksum_ReturnsObjectWithNullChecksum()
    {
        var spdxExternalDocumentReference = new SpdxExternalDocumentReference
        {
            ExternalDocumentId = "ExternalDocId",
            SpdxDocument = "https://example.com/spdx-document",
            Checksum = null
        };

        var externalDocumentReferenceInfo = spdxExternalDocumentReference.ToExternalDocumentReferenceInfo();

        Assert.IsNotNull(externalDocumentReferenceInfo);
        Assert.AreEqual(spdxExternalDocumentReference.ExternalDocumentId, externalDocumentReferenceInfo.ExternalDocumentName);
        Assert.AreEqual(spdxExternalDocumentReference.SpdxDocument, externalDocumentReferenceInfo.DocumentNamespace);
        Assert.IsNull(externalDocumentReferenceInfo.Checksum.First());
    }
}
