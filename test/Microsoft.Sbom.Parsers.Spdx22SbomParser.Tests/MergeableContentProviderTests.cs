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
    private IMergeableContentProviderInternal provider;

    [TestInitialize]
    public void BeforeEachTest()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        provider = new MergeableContentProvider(fileSystemUtilsMock.Object);
    }

    [TestMethod]
    public void TryGetContent_FilePath_IsNull_ThrowsArgumentNullException()
    {
        string filePath = null;
        Assert.ThrowsException<ArgumentNullException>(() => provider.TryGetContent(filePath, out _));
    }

    [TestMethod]
    public void TryGetContent_FilePath_FileDoesNotExist_ReturnsFalseAndNullContent()
    {
        const string nonExistentFilePath = "nonexistent-file.json";

        fileSystemUtilsMock.Setup(m => m.FileExists(nonExistentFilePath)).Returns(false);

        var result = provider.TryGetContent(nonExistentFilePath, out var mergeableContent);
        Assert.IsFalse(result);
        Assert.IsNull(mergeableContent);
    }

    [TestMethod]
    public void TryGetContent_FilePath_FileIsValid_ReturnsExpectedContent()
    {
        var filePath = Path.GetFullPath(Path.Combine(
            Assembly.GetExecutingAssembly().Location, "..", "..", "..", "..", "..", "..", "samples", "spdx_2.2", "manifest.spdx.json"));
        fileSystemUtilsMock.Setup(m => m.FileExists(filePath)).Returns(true);
        fileSystemUtilsMock.Setup(m => m.OpenRead(filePath)).Returns(() => new FileStream(filePath, FileMode.Open, FileAccess.Read));

        var result = provider.TryGetContent(filePath, out var mergeableContent);

        Assert.IsTrue(result);
        Assert.IsNotNull(mergeableContent);

        Assert.AreEqual(267, mergeableContent.Packages.Count());
        Assert.AreEqual(0, mergeableContent.Relationships.Count());
    }

    [TestMethod]
    public void TryGetContent_Stream_IsNull_ThrowsArgumentNullException()
    {
        Stream stream = null;
        Assert.ThrowsException<ArgumentNullException>(() => provider.TryGetContent(stream, out _));
    }

    [TestMethod]
    public void TryGetContent_Stream_IsInvalid_ReturnsFalseAndNullContent()
    {
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("This is not a valid manifest"));
        var result = provider.TryGetContent(stream, out var mergeableContent);

        Assert.IsFalse(result);
        Assert.IsNull(mergeableContent);
    }
}
