// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Text;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.JsonStrings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomPackageParserTests : SbomParserTestsBase
{
    [TestMethod]
    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingNameJsonString, "was missing required properties including: 'name'")]
    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingSpdxIdJsonString, "was missing required properties including: 'spdxId'")]
    public void MissingPropertiesTest_Throws(string json, string expectedMessage)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        var exception = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
        Assert.IsTrue(exception.Message.Contains(expectedMessage), $"Expected message to contain: {expectedMessage}, but was: {exception.Message}");
    }

    [TestMethod]
    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingVerificationJsonString)]
    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingSHA256JsonString)]
    public void MissingPropertiesTest_Succeeds(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        var result = this.Parse(parser);
        Assert.AreEqual(1, result.PackagesCount);
    }

    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingVerificationJsonString)]
    [DataRow(SbomFullDocWithPackagesStrings.SbomPackageWithMissingSHA256JsonString)]
    [TestMethod]
    public void MissingPropertiesTest_NTIA_VerificationCode_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithPackagesStrings.SbomPackageWithMissingVerificationJsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var exception = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
        var expectedMessage = "SBOM document is not NTIA compliant because package with SPDX ID";
        Assert.IsTrue(exception.Message.Contains(expectedMessage), $"Expected message to contain: {expectedMessage}, but was: {exception.Message}");
    }

    [TestMethod]
    public void IgnoresAdditionalPropertiesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithPackagesStrings.SbomPackageWithAdditionalPropertiesJsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        var result = this.Parse(parser);
        Assert.AreEqual(1, result.PackagesCount);
    }

    [TestMethod]
    public void ValidNTIA_Succeeds()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithPackagesStrings.SbomNTIAValidPackageJsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var result = this.Parse(parser);
        Assert.AreEqual(1, result.PackagesCount);
    }
}
