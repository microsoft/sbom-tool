// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
    public enum GenerationConstructionMode
    {
        UseDefaultWithDefaults,
        UseDefaultWithBool,
        UseConfiguration,
    }

    public enum AggregationConstructionMode
    {
        UseDefaultWithBool,
        UseConfiguration,
    }

    private const string ExpectedFormatSpdxId = "SPDXRef-Package-C8D4982D8356503F1912C637E4DFB7A53400AF98C08BA4732BB9F3CF70F628A9";

    private Mock<IConfiguration> configurationMock;

    [TestInitialize]
    public void BeforeEachTest()
    {
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        configurationMock.VerifyAll();
    }

    [TestMethod]
    [DataRow(GenerationConstructionMode.UseDefaultWithDefaults)]
    [DataRow(GenerationConstructionMode.UseDefaultWithBool)]
    [DataRow(GenerationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocumentTest_FilesAnalyzed_IsFalse(GenerationConstructionMode mode)
    {
        var generator = BuildGenerationGenerator(mode);

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
    [DataRow(GenerationConstructionMode.UseDefaultWithDefaults)]
    [DataRow(GenerationConstructionMode.UseDefaultWithBool)]
    [DataRow(GenerationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocumentTest_FilesAnalyzed_IsTrue(GenerationConstructionMode mode)
    {
        var generator = BuildGenerationGenerator(mode);

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
    [DataRow(GenerationConstructionMode.UseDefaultWithDefaults)]
    [DataRow(GenerationConstructionMode.UseDefaultWithBool)]
    [DataRow(GenerationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocument_DependsOnId_Null_ReturnsEmptyList(GenerationConstructionMode mode)
    {
        var generator = BuildGenerationGenerator(mode);

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = null
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(0, result.ResultMetadata.DependOn.Count);
    }

    [TestMethod]

    [DataRow(AggregationConstructionMode.UseDefaultWithBool)]
    [DataRow(AggregationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocument_Aggregating_DependsOnId_ReturnsInputId(AggregationConstructionMode mode)
    {
        var generator = BuildAggregationGenerator(mode);

        const string packageId1 = "SomePackageId";
        const string packageId2 = Constants.RootPackageIdValue;
        const string packageId3 = ExpectedFormatSpdxId;

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { packageId1, packageId2, packageId3 }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(3, result.ResultMetadata.DependOn.Count);
        // Note that the order of the IDs in DependsOn is not guaranteed, so we check for their presence instead of exact order.
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(packageId1));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(packageId2));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(packageId3));
    }

    [TestMethod]
    [DataRow(GenerationConstructionMode.UseDefaultWithDefaults)]
    [DataRow(GenerationConstructionMode.UseDefaultWithBool)]
    [DataRow(GenerationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocument_Generating_DependsOnId_EqualsRootPackageId_ReturnsInputId(GenerationConstructionMode mode)
    {
        var generator = BuildGenerationGenerator(mode);

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
    [DataRow(GenerationConstructionMode.UseDefaultWithDefaults)]
    [DataRow(GenerationConstructionMode.UseDefaultWithBool)]
    [DataRow(GenerationConstructionMode.UseConfiguration)]
    public void GenerateJsonDocument_Generating_DependsOnId_NotRootPackageId_GeneratesNewPackageId(GenerationConstructionMode mode)
    {
        var generator = BuildGenerationGenerator(mode);

        const string packageId1 = "SomePackageId";
        const string packageId2 = "AnotherPackageId";
        const string packageId3 = ExpectedFormatSpdxId;

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { packageId1, packageId2, packageId3 }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(3, result.ResultMetadata.DependOn.Count);
        // Note that the order of the IDs in DependsOn is not guaranteed, so we check for their presence instead of exact order.
        var expectedDependOnId1 = CommonSPDXUtils.GenerateSpdxPackageId(packageId1);
        var expectedDependOnId2 = CommonSPDXUtils.GenerateSpdxPackageId(packageId2);
        var expectedDependOnId3 = CommonSPDXUtils.GenerateSpdxPackageId(packageId3);
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId1));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId2));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId3));
    }

    private Generator BuildGenerationGenerator(GenerationConstructionMode mode)
    {
        switch (mode)
        {
            case GenerationConstructionMode.UseDefaultWithDefaults:
                return new Generator();
            case GenerationConstructionMode.UseDefaultWithBool:
                return new Generator(false);
            case GenerationConstructionMode.UseConfiguration:
                configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Generate);
                return new Generator(configurationMock.Object);
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
    }

    private Generator BuildAggregationGenerator(AggregationConstructionMode mode)
    {
        switch (mode)
        {
            case AggregationConstructionMode.UseDefaultWithBool:
                return new Generator(true);
            case AggregationConstructionMode.UseConfiguration:
                configurationMock.SetupGet(m => m.ManifestToolAction).Returns(ManifestToolActions.Aggregate);
                return new Generator(configurationMock.Object);
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
    }
}
