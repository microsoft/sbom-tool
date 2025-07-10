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
using Serilog;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Tests;

[TestClass]
public class MergeableContentProviderTests
{
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<ILogger> loggerMock;
    private IMergeableContentProvider provider;

    [TestInitialize]
    public void BeforeEachTest()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        loggerMock = new Mock<ILogger>(); // Intentionaly not using Strict behavior for logger
        provider = new MergeableContentProvider(fileSystemUtilsMock.Object, loggerMock.Object);
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
    public void TryGetContent_FileExistsAndIsValid_ReturnsExpectedContent()
    {
        const string filePathFileExistsAndIsValid = "valid-manifest-file.json";
        const string expectedMappedRootPackageId = "SPDXRef-Package-AB9E9DFAA1DE5301A6059720D507F78282B83DA56D6829ED7965987E7FCCAC3B";
        const string expectedRootPackageName = "sbom-tool sample";
        const int expectedPackageCount = 267;
        const int expectedRelationshipCount = 267;
        const int expectedUnmappedRootDependenciesCount = 48;

        fileSystemUtilsMock.Setup(m => m.FileExists(filePathFileExistsAndIsValid)).Returns(true);
        fileSystemUtilsMock.Setup(m => m.OpenRead(filePathFileExistsAndIsValid))
            .Returns(() => Assembly.GetExecutingAssembly().GetManifestResourceStream("Microsoft.Sbom.manifest.spdx.json"));

        var result = provider.TryGetContent(filePathFileExistsAndIsValid, out var mergeableContent);

        Assert.IsTrue(result);
        Assert.IsNotNull(mergeableContent);

        Assert.AreEqual(expectedPackageCount, mergeableContent.Packages.Count());
        Assert.AreEqual(expectedRelationshipCount, mergeableContent.Relationships.Count());
        Assert.AreEqual(0, mergeableContent.Packages.Count(p => p.Id == Constants.RootPackageIdValue));
        Assert.AreEqual(0, mergeableContent.Relationships.Count(r => r.TargetElementId == Constants.RootPackageIdValue));

        // Ensure that we successfully completed the package remapping
        var mappedRootPackages = mergeableContent.Packages.Where(p => p.Id == expectedMappedRootPackageId).ToList();
        Assert.AreEqual(1, mappedRootPackages.Count);
        Assert.AreEqual(expectedRootPackageName, mappedRootPackages[0].PackageName);

        var unmappedRootDependencies = mergeableContent.Relationships.Where(r => r.SourceElementId == mappedRootPackages[0].Id).ToList();
        Assert.AreEqual(expectedUnmappedRootDependenciesCount, unmappedRootDependencies.Count);

        var mappedRootDependencies = mergeableContent.Relationships.Where(r => r.SourceElementId == Constants.RootPackageIdValue).ToList();
        Assert.AreEqual(1, mappedRootDependencies.Count);
        Assert.AreEqual(Constants.RootPackageIdValue, mappedRootDependencies[0].SourceElementId);
        Assert.AreEqual(expectedMappedRootPackageId, mappedRootDependencies[0].TargetElementId);
    }
}
