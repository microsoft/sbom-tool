// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Linq;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class SPDXFormatDetectorTests
{
    private Mock<IFileSystemUtils> mockFileSystemUtils;
    private Mock<IManifestParserProvider> mockManifestParserProvider;
    private Mock<IManifestInterface> mock22ManifestInterface;
    private Mock<IManifestInterface> mock30ManifestInterface;
    private Mock<ISbomConfigFactory> mockSbomConfigFactory;
    private SPDXFormatDetector testSubject;

    private const string DirPathStub = "dir-path";
    private const string FilePathStub = "file-path";
    private const string Spdx22VersionStub = "SPDX:2.2";
    private const string Spdx30VersionStub = "SPDX:3.0";
    private const string Spdx22ContentStub = @"{""spdxVersion"": ""SPDX-2.2"",""files"":[],""packages"":[],""relationships"":[],""externalDocumentRefs"":[]}";
    private const string Spdx30ContentStub = @"{""@context"": [""https://Spdx.org/rdf/3.0.1/Spdx-context.jsonld""],""@graph"": []}";
    private const string InvalidContentStub = "invalid-content";

    [TestInitialize]
    public void SetUp()
    {
        mockFileSystemUtils = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        mockManifestParserProvider = new Mock<IManifestParserProvider>(MockBehavior.Strict);
        mock22ManifestInterface = new Mock<IManifestInterface>(MockBehavior.Strict);
        mock30ManifestInterface = new Mock<IManifestInterface>(MockBehavior.Strict);
        mockSbomConfigFactory = new Mock<ISbomConfigFactory>(MockBehavior.Strict);

        mockManifestParserProvider.Setup(m => m.Get(ManifestInfo.Parse(Spdx22VersionStub))).Returns(mock22ManifestInterface.Object);
        mockManifestParserProvider.Setup(m => m.Get(ManifestInfo.Parse(Spdx30VersionStub))).Returns(mock30ManifestInterface.Object);
        mock22ManifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>())).Returns((Stream stream) => new SPDXParser(stream));
        mock30ManifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>())).Returns((Stream stream) => new SPDX30Parser(stream));

        testSubject = new SPDXFormatDetector(mockFileSystemUtils.Object, mockManifestParserProvider.Object, mockSbomConfigFactory.Object);
    }

    [TestCleanup]
    public void Verify()
    {
        mockFileSystemUtils.VerifyAll();
        mockSbomConfigFactory.VerifyAll();
    }

    [TestMethod]
    [DataRow(Spdx22ContentStub, Spdx22VersionStub)]
    [DataRow(Spdx30ContentStub, Spdx30VersionStub)]
    public void TryGetSbomsWithVersion_SingleResult_Success(string testContent, string expectedVersion)
    {
        var spdx22FilePathStub = FilePathStub + Spdx22VersionStub;
        var spdx30FilePathStub = FilePathStub + Spdx30VersionStub;
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX22ManifestInfo))
            .Returns(spdx22FilePathStub);
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX30ManifestInfo))
            .Returns(spdx30FilePathStub);
        mockFileSystemUtils
            .Setup(m => m.FileExists(It.IsAny<string>()))
            .Returns(false);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + expectedVersion))
            .Returns(true);
        mockFileSystemUtils
            .Setup(m => m.GetFileSize(FilePathStub + expectedVersion))
            .Returns(1);
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub + expectedVersion))
            .Returns(TestUtils.GenerateStreamFromString(testContent));

        var result = testSubject.TryGetSbomsWithVersion(DirPathStub, out var detectedSboms);
        Assert.IsTrue(result);
        Assert.IsNotNull(detectedSboms);
        Assert.AreEqual(1, detectedSboms.Count());
        Assert.IsTrue(detectedSboms.Any(value => value.manifestInfo.ToString().Equals(expectedVersion) && value.sbomFilePath.Equals(FilePathStub + expectedVersion)), $"Files of format {expectedVersion} should have been detected");
    }

    [TestMethod]
    public void TryGetSbomsWithVersion_MultipleResults_Success()
    {
        var spdx22FilePathStub = FilePathStub + Spdx22VersionStub;
        var spdx30FilePathStub = FilePathStub + Spdx30VersionStub;
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX22ManifestInfo))
            .Returns(spdx22FilePathStub);
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX30ManifestInfo))
            .Returns(spdx30FilePathStub);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx22VersionStub))
            .Returns(true);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx30VersionStub))
            .Returns(true);
        mockFileSystemUtils
            .Setup(m => m.GetFileSize(FilePathStub + Spdx22VersionStub))
            .Returns(1);
        mockFileSystemUtils
            .Setup(m => m.GetFileSize(FilePathStub + Spdx30VersionStub))
            .Returns(1);
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub + Spdx22VersionStub))
            .Returns(TestUtils.GenerateStreamFromString(Spdx22ContentStub));
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub + Spdx30VersionStub))
            .Returns(TestUtils.GenerateStreamFromString(Spdx30ContentStub));

        var result = testSubject.TryGetSbomsWithVersion(DirPathStub, out var detectedSboms);
        Assert.IsTrue(result);
        Assert.IsNotNull(detectedSboms);
        Assert.AreEqual(2, detectedSboms.Count());
        Assert.IsTrue(detectedSboms.Any(value => value.manifestInfo.ToString().Equals(Spdx22VersionStub) && value.sbomFilePath.Equals(FilePathStub + Spdx22VersionStub)), "SPDX 2.2 files should have been detected");
        Assert.IsTrue(detectedSboms.Any(value => value.manifestInfo.ToString().Equals(Spdx30VersionStub) && value.sbomFilePath.Equals(FilePathStub + Spdx30VersionStub)), "SPDX 3.0 files should have been detected");
    }

    [TestMethod]
    public void TryGetSbomsWithVersion_NoResults()
    {
        var spdx22FilePathStub = FilePathStub + Spdx22VersionStub;
        var spdx30FilePathStub = FilePathStub + Spdx30VersionStub;
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX22ManifestInfo))
            .Returns(spdx22FilePathStub);
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX30ManifestInfo))
            .Returns(spdx30FilePathStub);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx22VersionStub))
            .Returns(false);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx30VersionStub))
            .Returns(false);

        var result = testSubject.TryGetSbomsWithVersion(DirPathStub, out var detectedSboms);
        Assert.IsFalse(result);
        Assert.IsNotNull(detectedSboms);
        Assert.IsFalse(detectedSboms.Any());
    }

    [TestMethod]
    public void TryGetSbomsWithVersion_FilesAreEmpty()
    {
        var spdx22FilePathStub = FilePathStub + Spdx22VersionStub;
        var spdx30FilePathStub = FilePathStub + Spdx30VersionStub;
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX22ManifestInfo))
            .Returns(spdx22FilePathStub);
        mockSbomConfigFactory
            .Setup(m => m.GetSbomFilePath(DirPathStub, Api.Utils.Constants.SPDX30ManifestInfo))
            .Returns(spdx30FilePathStub);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx22VersionStub))
            .Returns(true);
        mockFileSystemUtils
            .Setup(m => m.FileExists(FilePathStub + Spdx30VersionStub))
            .Returns(true);
        mockFileSystemUtils
            .Setup(m => m.GetFileSize(FilePathStub + Spdx22VersionStub))
            .Returns(0);
        mockFileSystemUtils
            .Setup(m => m.GetFileSize(FilePathStub + Spdx30VersionStub))
            .Returns(0);

        var result = testSubject.TryGetSbomsWithVersion(DirPathStub, out var detectedSboms);
        Assert.IsFalse(result);
        Assert.IsNotNull(detectedSboms);
        Assert.IsFalse(detectedSboms.Any());
    }

    [TestMethod]
    [DataRow(Spdx22ContentStub, Spdx22VersionStub)]
    [DataRow(Spdx30ContentStub, Spdx30VersionStub)]
    public void TryDetectFormat_FilePath_Success(string testContent, string expectedVersion)
    {
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub))
            .Returns(TestUtils.GenerateStreamFromString(testContent));

        var result = testSubject.TryDetectFormat(FilePathStub, out var manifestInfo);
        Assert.IsTrue(result);
        Assert.IsNotNull(manifestInfo);
        Assert.AreEqual(expectedVersion, manifestInfo.ToString());
    }

    [TestMethod]
    [DataRow(Spdx22ContentStub, Spdx22VersionStub)]
    [DataRow(Spdx30ContentStub, Spdx30VersionStub)]
    public void TryDetectFormat_Stream_Success(string testContent, string expectedVersion)
    {
        var result = testSubject.TryDetectFormat(TestUtils.GenerateStreamFromString(testContent), out var manifestInfo);
        Assert.IsTrue(result);
        Assert.IsNotNull(manifestInfo);
        Assert.AreEqual(ManifestInfo.Parse(expectedVersion), manifestInfo);
    }

    [TestMethod]
    public void TryDetectFormat_FilePath_InvalidVersion()
    {
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub))
            .Returns(TestUtils.GenerateStreamFromString(InvalidContentStub));

        var result = testSubject.TryDetectFormat(FilePathStub, out var manifestInfo);
        Assert.IsFalse(result);
        Assert.IsNull(manifestInfo);
    }

    [TestMethod]
    public void TryDetectFormat_Stream_InvalidVersion()
    {
        var result = testSubject.TryDetectFormat(TestUtils.GenerateStreamFromString(InvalidContentStub), out var manifestInfo);
        Assert.IsFalse(result);
        Assert.IsNull(manifestInfo);
    }
}
