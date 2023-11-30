// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
        Assert.AreEqual(expected.ToString(), property.ToString());
    }
}
