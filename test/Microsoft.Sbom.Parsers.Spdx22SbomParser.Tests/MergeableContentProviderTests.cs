// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Tests;

[TestClass]
public class MergeableContentProviderTests
{
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private IMergeableContentProvider provider;

    [TestInitialize]
    public void BeforeEachTest()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        provider = new MergeableContentProvider(fileSystemUtilsMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public void TryGetContent_FilePathIsNull_ThrowsArgumentNullException()
    {
        string filePath = null;
        Assert.ThrowsException<ArgumentNullException>(() => provider.TryGetContent(filePath, out _));
    }

    [TestMethod]
    public void TryGetContent_FileDoesNotExist_ReturnsFalseAndNullContent()
    {
        const string filePathFileDoesNotExist = "nonexistent-file.json";

        fileSystemUtilsMock.Setup(m => m.FileExists(filePathFileDoesNotExist)).Returns(false);

        var result = provider.TryGetContent(filePathFileDoesNotExist, out var mergeableContent);
        Assert.IsFalse(result);
        Assert.IsNull(mergeableContent);
    }

    [TestMethod]
    public void TryGetContent_FileExistsButIsInvalid_ReturnsFalseAndNullContent()
    {
        const string filePathFileExistsButIsNotValid = "existing-but-invalid-manifest-file.json";

        fileSystemUtilsMock.Setup(m => m.FileExists(filePathFileExistsButIsNotValid)).Returns(true);
        fileSystemUtilsMock.Setup(m => m.OpenRead(filePathFileExistsButIsNotValid))
            .Returns(() => new MemoryStream(System.Text.Encoding.UTF8.GetBytes("This is not a valid manifest")));

        var result = provider.TryGetContent(filePathFileExistsButIsNotValid, out var mergeableContent);

        Assert.IsFalse(result);
        Assert.IsNull(mergeableContent);
    }

    [TestMethod]
    public void TryGetContent_FileExitstAndIsValid_ReturnsExpectedContent()
    {
        const string filePathFileExistsAndIsValid = "valid-manifest-file.json";

        fileSystemUtilsMock.Setup(m => m.FileExists(filePathFileExistsAndIsValid)).Returns(true);
        fileSystemUtilsMock.Setup(m => m.OpenRead(filePathFileExistsAndIsValid))
            .Returns(() => Assembly.GetExecutingAssembly().GetManifestResourceStream("Microsoft.Sbom.manifest.spdx.json"));

        var result = provider.TryGetContent(filePathFileExistsAndIsValid, out var mergeableContent);

        Assert.IsTrue(result);
        Assert.IsNotNull(mergeableContent);

        Assert.AreEqual(267, mergeableContent.Packages.Count());
        Assert.AreEqual(266, mergeableContent.Relationships.Count());
    }
}
