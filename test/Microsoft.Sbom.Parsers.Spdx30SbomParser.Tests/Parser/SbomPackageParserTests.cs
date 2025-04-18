// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.Common.ComplianceStandard.Enums;
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
    public void MissingPropertiesTest_SPDX_Throws(string json, string expectedMessage)
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
    public void MissingPropertiesTest_SPDX_VerificationCode_Succeeds(string json)
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
        parser.EnforceComplianceStandard(Contracts.Enums.ComplianceStandardType.NTIA);
        var result = this.Parse(parser);

        Assert.AreEqual(1, result.InvalidComplianceStandardElements.Count);

        var invalidElement = result.InvalidComplianceStandardElements.First();
        Assert.AreEqual("SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE", invalidElement.SpdxId);
        Assert.AreEqual("test", invalidElement.Name);
        Assert.AreEqual(NTIAErrorType.InvalidNTIAElement, invalidElement.ErrorType);
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
        parser.EnforceComplianceStandard(Contracts.Enums.ComplianceStandardType.NTIA);
        var result = this.Parse(parser);
        Assert.AreEqual(1, result.PackagesCount);
    }
}
