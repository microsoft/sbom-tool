// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser;

using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class CommonSPDXUtilsTests
{
    [TestMethod]
    public void GenerateSpdxPackageIdTest()
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxPackageId("test");
        Assert.IsTrue(spdxId.Contains(Constants.SPDXRefPackage));
    }

    [TestMethod]
    public void GenerateSpdxPackageIdTest_SameStrings()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxPackageId("test1");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxPackageId("test2");
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxPackageIdTest_DiffStrings()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxPackageId("test1");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxPackageId("test1");
        Assert.AreEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest()
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxFileId("test", "sha1Value");
        Assert.IsTrue(spdxId.Contains(Constants.SPDXRefFile));
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest_SameNameAndSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxFileId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxFileId("test1", "sha1Value");
        Assert.AreEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest_DiffName()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxFileId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxFileId("test2", "sha1Value");
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxFileIdTest_DiffSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxFileId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxFileId("test1", "sha2Value");
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest()
    {
        var spdxId = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test", "sha1Value");
        Assert.IsTrue(spdxId.Contains(Constants.SPDXRefExternalDocument));
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest_SameNameAndSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test1", "sha1Value");
        Assert.AreEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest_DiffName()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test2", "sha1Value");
        Assert.AreNotEqual(spdxId1, spdxId2);
    }

    [TestMethod]
    public void GenerateSpdxExternalDocumentIdTest_DiffSha1Value()
    {
        var spdxId1 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test1", "sha1Value");
        var spdxId2 = CommonSPDXUtils.GenerateSpdxExternalDocumentId("test1", "sha2Value");
        Assert.AreNotEqual(spdxId1, spdxId2);
    }
}
