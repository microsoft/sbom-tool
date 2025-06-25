// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
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
    private SPDXFormatDetector testSubject;

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

        mockManifestParserProvider.Setup(m => m.Get(ManifestInfo.Parse(Spdx22VersionStub))).Returns(mock22ManifestInterface.Object);
        mockManifestParserProvider.Setup(m => m.Get(ManifestInfo.Parse(Spdx30VersionStub))).Returns(mock30ManifestInterface.Object);
        mock22ManifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>())).Returns((Stream stream) => new SPDXParser(stream));
        mock30ManifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>())).Returns((Stream stream) => new SPDX30Parser(stream));

        testSubject = new SPDXFormatDetector(mockFileSystemUtils.Object, mockManifestParserProvider.Object);
    }

    [TestCleanup]
    public void Verify()
    {
        mockFileSystemUtils.VerifyAll();
    }

    [TestMethod]
    [DataRow(Spdx22ContentStub, Spdx22VersionStub)]
    [DataRow(Spdx30ContentStub, Spdx30VersionStub)]
    public void TryDetectFormat_FilePath_Success(string testContent, string expectedVersion)
    {
        mockFileSystemUtils
            .Setup(m => m.OpenRead(FilePathStub))
            .Returns(TestUtils.GenerateStreamFromString(testContent))
            .Verifiable();

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
            .Returns(TestUtils.GenerateStreamFromString(InvalidContentStub))
            .Verifiable();

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
