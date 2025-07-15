// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class GeneratorTests
{
    private const string ExpectedFormatSpdxId = "SPDXRef-Package-C8D4982D8356503F1912C637E4DFB7A53400AF98C08BA4732BB9F3CF70F628A9";

    private Mock<IConfiguration> configurationMock;
    private Generator generator;

    [TestInitialize]
    public void BeforeEachTest()
    {
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        generator = new Generator(configurationMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        configurationMock.VerifyAll();
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_FilesAnalyzed_IsFalse()
    {
        const string PackageUrl = "packageUrl";
        var packageInfo = new SbomPackage
        {
            PackageName = "test",
            PackageUrl = PackageUrl,
            FilesAnalyzed = false
        };

        var result = generator.GenerateJsonDocument(packageInfo);
        var propertyExists = result.Document.RootElement.TryGetProperty("licenseInfoFromFiles", out var property);

        Assert.IsFalse(propertyExists);
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_FilesAnalyzed_IsTrue()
    {
        var expected = "[\"NOASSERTION\"]";

        const string PackageUrl = "packageUrl";
        var packageInfo = new SbomPackage
        {
            PackageName = "test",
            PackageUrl = PackageUrl,
            FilesAnalyzed = true
        };

        var result = generator.GenerateJsonDocument(packageInfo);
        var propertyExists = result.Document.RootElement.TryGetProperty("licenseInfoFromFiles", out var property);

        Assert.IsTrue(propertyExists);
        Assert.AreEqual(expected, property.ToString());
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_Null_ReturnsEmptyList()
    {
        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = null
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(0, result.ResultMetadata.DependOn.Count);
    }

    [TestMethod]
    public void GenerateJsonDocument_Aggregating_DependsOnId_EqualsRootPackageId_ReturnsInputId()
    {
        configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Aggregate);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { Constants.RootPackageIdValue }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(1, result.ResultMetadata.DependOn.Count);
        Assert.AreEqual(Constants.RootPackageIdValue, result.ResultMetadata.DependOn[0]);
    }

    [TestMethod]
    public void GenerateJsonDocument_Aggregating_DependsOnId_IsWellFormedId_ReturnsInputId()
    {
        configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Aggregate);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { ExpectedFormatSpdxId }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(1, result.ResultMetadata.DependOn.Count);
        Assert.AreEqual(ExpectedFormatSpdxId, result.ResultMetadata.DependOn[0]);
    }

    [TestMethod]
    public void GenerateJsonDocument_Generating_DependsOnId_EqualsRootPackageId_DoesNotReturnInputId()
    {
        configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Generate);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { Constants.RootPackageIdValue }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(1, result.ResultMetadata.DependOn.Count);
        Assert.AreNotEqual(Constants.RootPackageIdValue, result.ResultMetadata.DependOn[0]);
    }

    [TestMethod]
    public void GenerateJsonDocument_Generating_DependsOnId_IsWellFormedId_ReturnsInputId()
    {
        configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Generate);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { ExpectedFormatSpdxId }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(1, result.ResultMetadata.DependOn.Count);
        Assert.AreNotEqual(ExpectedFormatSpdxId, result.ResultMetadata.DependOn[0]);
    }

    [TestMethod]
    [DataRow(ManifestToolActions.Generate)]
    [DataRow(ManifestToolActions.Aggregate)]
    public void GenerateJsonDocument_DependsOnId_ValidListOfValues_GeneratesSpdxPackageId(ManifestToolActions action)
    {
        const string packageId1 = "SomePackageId";
        const string packageId2 = "AnotherPackageId";

        configurationMock.SetupGet(m => m.ManifestToolAction).Returns(action);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { packageId1, packageId2 }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(2, result.ResultMetadata.DependOn.Count);
        // Note that the order of the IDs in DependsOn is not guaranteed, so we check for their presence instead of exact order.
        var expectedDependOnId1 = CommonSPDXUtils.GenerateSpdxPackageId(packageId1);
        var expectedDependOnId2 = CommonSPDXUtils.GenerateSpdxPackageId(packageId2);
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId1));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId2));
    }
}
