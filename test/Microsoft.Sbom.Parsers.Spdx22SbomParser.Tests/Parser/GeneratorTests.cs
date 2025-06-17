// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class GeneratorTests
{
    [TestMethod]
    public void GenerateJsonDocumentTest_FilesAnalyzed_IsFalse()
    {
        var generator = new Generator();

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
        var generator = new Generator();
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
        var generator = new Generator();

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = null
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(0, result.ResultMetadata.DependOn.Count);
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_EqualsRootPackageId_ReturnsRootPackageId()
    {
        var generator = new Generator();

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { Constants.RootPackageIdValue }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(Constants.RootPackageIdValue));
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_ValidListOfValues_GeneratesSpdxPackageId()
    {
        var generator = new Generator();

        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = new List<string> { "SomePackageId", "AnotherPackageId" }
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        var expectedDependOnId1 = CommonSPDXUtils.GenerateSpdxPackageId("SomePackageId");
        var expectedDependOnId2 = CommonSPDXUtils.GenerateSpdxPackageId("AnotherPackageId");
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId1));
        Assert.IsTrue(result.ResultMetadata.DependOn.Contains(expectedDependOnId2));
        Assert.AreEqual(2, result.ResultMetadata.DependOn.Count);
    }
}
