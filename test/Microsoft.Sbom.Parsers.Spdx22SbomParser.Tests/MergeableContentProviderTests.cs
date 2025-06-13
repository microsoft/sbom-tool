// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Sbom.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Tests;

[TestClass]
public class MergeableContentProviderTests
{
    private IMergeableContentProviderInternal provider;

    [TestInitialize]
    public void BeforeEachTest()
    {
        provider = new MergeableContentProvider();
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
        var result = provider.TryGetContent("nonexistent-file.json", out var mergeableContent);
        Assert.IsFalse(result);
        Assert.IsNull(mergeableContent);
    }

    [TestMethod]
    public void TryGetContent_FilePath_FileIsValid_ReturnsExpectedContent()
    {
        var filePath = Path.GetFullPath(Path.Combine(
            Assembly.GetExecutingAssembly().Location, "..", "..", "..", "..", "..", "..", "samples", "manifest.spdx.json"));
        var result = provider.TryGetContent(filePath, out var mergeableContent);

        Assert.IsTrue(result);
        Assert.IsNotNull(mergeableContent);

        Assert.AreEqual(72, mergeableContent.Packages.Count());
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
