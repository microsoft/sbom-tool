// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser;

using System.Data;
using Microsoft.Sbom.Common.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class CommonSPDXUtilsTests
{
    private const string TestPackage1 = "testPackage1";
    private const string TestPackage2 = "testPackage2";
    private const string TestPackage1SpdxId = "SPDXRef-Package-17BE63B07D94E1FDAFCC6AD9F7DB98CC90A7A17744E94C045A10FE15DD426FFE";
    private const string TestPackage2SpdxId = "SPDXRef-Package-B7A5E408E59C8D95B09020EA79327C05272A8EE8C6B11331775A004AA0EED04D";

    private const string TestFile1 = "testFile1";
    private const string TestFile2 = "testFile2";

    private const string TestExternalDoc1 = "testExternalDoc1";
    private const string TestExternalDoc2 = "testExternalDoc2";

    private const string TestHash1 = "sha1Value1";
    private const string TestHash2 = "sha1Value2";

    private const string TestFile1Hash1SpdxId = "SPDXRef-File-testFile1-sha1Value1";
    private const string TestFile2Hash2SpdxId = "SPDXRef-File-testFile2-sha1Value2";
    private const string TestExternalDoc1Hash1SpdxId = "DocumentRef-testExternalDoc1-sha1Value1";
    private const string TestExternalDoc2Hash2SpdxId = "DocumentRef-testExternalDoc2-sha1Value2";

    [DataRow(TestPackage1, TestPackage1SpdxId)]
    [DataRow(TestPackage2, TestPackage2SpdxId)]
    [TestMethod]
    public void GenerateSpdxPackageIdTest(string package, string expectedSpdxId)
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxPackageId(package);
        Assert.AreEqual(expectedSpdxId, spdxId);
    }

    [DataRow(TestFile1, TestHash1, TestFile1Hash1SpdxId)]
    [DataRow(TestFile2, TestHash2, TestFile2Hash2SpdxId)]
    [TestMethod]
    public void GenerateSpdxFileIdTest(string file, string sha1Value, string expectedSpdxId)
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxFileId(file, sha1Value);
        Assert.AreEqual(expectedSpdxId, spdxId);
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest_DiffName()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxFileId(TestFile1, TestHash1);
        var spdxId2 = CommonSPDXUtils.GenerateSpdxFileId(TestFile2, TestHash1);
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest_DiffSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxFileId(TestFile1, TestHash1);
        var spdxId2 = CommonSPDXUtils.GenerateSpdxFileId(TestFile1, TestHash2);
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [DataRow(TestExternalDoc1, TestHash1, TestExternalDoc1Hash1SpdxId)]
    [DataRow(TestExternalDoc2, TestHash2, TestExternalDoc2Hash2SpdxId)]
    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest(string externalDoc, string sha1value, string expectedSpdxId)
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxExternalDocumentId(externalDoc, sha1value);
        Assert.AreEqual(expectedSpdxId, spdxId);
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest_DiffName()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxExternalDocumentId(TestExternalDoc1, TestHash1);
        var spdxId2 = CommonSPDXUtils.GenerateSpdxExternalDocumentId(TestExternalDoc2, TestHash1);
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest_DiffSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxExternalDocumentId(TestExternalDoc1, TestHash1);
        var spdxId2 = CommonSPDXUtils.GenerateSpdxExternalDocumentId(TestExternalDoc1, TestHash2);
        Assert.AreNotEqual(spdxId1, spdxId2);
    }
}
