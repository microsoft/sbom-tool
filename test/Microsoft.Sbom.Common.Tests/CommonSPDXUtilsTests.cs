// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Data;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

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

    private const string TestPackageVersion = "1.2.3";
    private const string TestPackageType = "TestPackageType";

    private const string ConstantPackageRoot = "SPDXRef-RootPackage";

    private const string TestPackage1WithPackageSpdxId = "SPDXRef-Package-20D44930AAC47CD0742168EF1B379150FD6687B216B77D6206FACFF56F0FE17B";
    private const string TestPackage1WithPackageAndVersionSpdxId = "SPDXRef-Package-58C5DD56550594F89AB94FBE3702CC8D0DCB06D5C781305938449FBF9E309196";
    private const string TestPackage1WithPackageAndVersionAndTypeSpdxId = "SPDXRef-Package-E3FD92B139AF7424535396792FA2B2D70EB715EA83D24E497A6C716279227735";
    private const string TestPackage1WithPackageAndTypeSpdxId = "SPDXRef-Package-F79E2B8CF0C894FA3991089088856FA215B7B196872B8AD653ADA4810F78F33C";
    private const string ConstantPackageRootSpdxId = "SPDXRef-Package-27C5AE25932C81815EFD8B210DAA1A017B4A461AF82DE1405906163A2D5573BB";

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
    [DataRow(null, TestPackage1, null, null, TestPackage1WithPackageSpdxId)]
    [DataRow(null, TestPackage1, TestPackageVersion, null, TestPackage1WithPackageAndVersionSpdxId)]
    [DataRow(null, TestPackage1, TestPackageVersion, TestPackageType, TestPackage1WithPackageAndVersionAndTypeSpdxId)]
    [DataRow(null, TestPackage1, null, TestPackageType, TestPackage1WithPackageAndTypeSpdxId)]
    [DataRow(TestPackage1SpdxId, null, null, null, TestPackage1SpdxId)]
    [DataRow(TestPackage1SpdxId, TestPackageType, TestPackageVersion, TestPackageType, TestPackage1SpdxId)]
    [DataRow(ConstantPackageRoot, null, null, null, ConstantPackageRootSpdxId)]
    public void GenerateSpdxFileId_Packages(string packageId, string packageName, string packageVersion, string type, string expectedSpdxId)
    {
        var packageInfo = new SbomPackage
        {
            Id = packageId,
            PackageName = packageName,
            PackageVersion = packageVersion,
            Type = type,
        };
        var spdxId = CommonSPDXUtils.GenerateSpdxPackageId(packageInfo);
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
