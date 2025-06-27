// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.Manifest.Configuration;

[TestClass]
public class SbomConfigFactoryTests
{
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IMetadataBuilderFactory> metadataBuilderFactoryMock;
    private SbomConfigFactory testSubject;

    private string manifestDirPathStub = "manifest-dir-path";
    private string spdxDirPathStub = "spdx-dir-path";
    private string sbomFilePathStub = "sbom-file-path";
    private string catFilePathStub = "cat-file-path";
    private string cbCatFilePathStub = "cloud-build-cat-file-path";
    private string bsiFilePathStub = "bsi-file-path";
    private string cbBsiFilePathStub = "cloud-build-bsi-file-path";
    private ManifestInfo manifestInfoStub = Api.Utils.Constants.SPDX30ManifestInfo;
    private string manifestInfoStringStub = "spdx_3.0";
    private string manifestFileNameStub = "manifest.spdx.json";
    private IMetadataBuilder metadataBuilderStub = new Mock<IMetadataBuilder>().Object;

    [TestInitialize]
    public void BeforeEachTest()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        metadataBuilderFactoryMock = new Mock<IMetadataBuilderFactory>(MockBehavior.Strict);

        testSubject = new SbomConfigFactory(fileSystemUtilsMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        fileSystemUtilsMock.VerifyAll();
        metadataBuilderFactoryMock.VerifyAll();
    }

    [TestMethod]
    public void GetSpdxDirPath_ReturnsValidPath()
    {
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, manifestInfoStringStub))
            .Returns(spdxDirPathStub)
            .Verifiable();

        var result = testSubject.GetSpdxDirPath(manifestDirPathStub, manifestInfoStub);
        Assert.AreEqual(spdxDirPathStub, result);
    }

    [TestMethod]
    public void GetSbomFilePath_ReturnsValidPath()
    {
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, manifestInfoStringStub))
            .Returns(spdxDirPathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, manifestFileNameStub))
            .Returns(sbomFilePathStub)
            .Verifiable();

        var result = testSubject.GetSbomFilePath(manifestDirPathStub, manifestInfoStub);
        Assert.AreEqual(sbomFilePathStub, result);
    }

    [TestMethod]
    public void Get_ReturnsCorrectConfig_AdoStyleSbom()
    {
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, manifestInfoStringStub))
            .Returns(spdxDirPathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, manifestFileNameStub))
            .Returns(sbomFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, Api.Utils.Constants.CatalogFileName))
            .Returns(catFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, Api.Utils.Constants.BsiFileName))
            .Returns(bsiFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.FileExists($"{sbomFilePathStub}.sha256"))
            .Returns(true)
            .Verifiable();
        metadataBuilderFactoryMock.Setup(m => m.Get(manifestInfoStub)).Returns(metadataBuilderStub).Verifiable();

        var result = testSubject.Get(manifestInfoStub, manifestDirPathStub, metadataBuilderFactoryMock.Object);
        Assert.AreEqual(manifestInfoStub, result.ManifestInfo);
        Assert.AreEqual(sbomFilePathStub, result.ManifestJsonFilePath);
        Assert.AreEqual(manifestDirPathStub, result.ManifestJsonDirPath);
        Assert.AreEqual($"{sbomFilePathStub}.sha256", result.ManifestJsonFileSha256FilePath);
        Assert.AreEqual(catFilePathStub, result.CatalogFilePath);
        Assert.AreEqual(bsiFilePathStub, result.BsiFilePath);
    }

    [TestMethod]
    public void Get_ReturnsCorrectConfig_CloudBuildStyleSbom()
    {
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, manifestInfoStringStub))
            .Returns(spdxDirPathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, manifestFileNameStub))
            .Returns(sbomFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, Api.Utils.Constants.CatalogFileName))
            .Returns(catFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(spdxDirPathStub, Api.Utils.Constants.BsiFileName))
            .Returns(bsiFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.FileExists($"{sbomFilePathStub}.sha256"))
            .Returns(false)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.FileExists(catFilePathStub))
            .Returns(false)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.FileExists(bsiFilePathStub))
            .Returns(false)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, Api.Utils.Constants.CatalogFileName))
            .Returns(cbCatFilePathStub)
            .Verifiable();
        fileSystemUtilsMock
            .Setup(m => m.JoinPaths(manifestDirPathStub, Api.Utils.Constants.BsiFileName))
            .Returns(cbBsiFilePathStub)
            .Verifiable();
        metadataBuilderFactoryMock.Setup(m => m.Get(manifestInfoStub)).Returns(metadataBuilderStub).Verifiable();

        var result = testSubject.Get(manifestInfoStub, manifestDirPathStub, metadataBuilderFactoryMock.Object);
        Assert.AreEqual(manifestInfoStub, result.ManifestInfo);
        Assert.AreEqual(sbomFilePathStub, result.ManifestJsonFilePath);
        Assert.AreEqual(manifestDirPathStub, result.ManifestJsonDirPath);
        Assert.IsNull(result.ManifestJsonFileSha256FilePath);
        Assert.AreEqual(cbCatFilePathStub, result.CatalogFilePath);
        Assert.AreEqual(cbBsiFilePathStub, result.BsiFilePath);
    }
}
