// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.Common.Conformance.Enums;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.JsonStrings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests : SbomParserTestsBase
{
    [TestMethod]
    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingNameJsonString)]
    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingSpdxIdJsonString)]
    public void MissingPropertiesTest_SPDX_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        _ = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingVerificationJsonString)]
    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingSHA256JsonString)]
    [TestMethod]
    public void MissingPropertiesTest_NTIA_NoVerificationCode_Throws(string jsonString)
    {
        var bytes = Encoding.UTF8.GetBytes(jsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        parser.EnforceConformance(Contracts.Enums.ConformanceType.NTIA);
        var result = this.Parse(parser);

        var invalidElement = result.InvalidConformanceElements.First();
        Assert.AreEqual("SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967", invalidElement.SpdxId);
        Assert.AreEqual("./sample/path", invalidElement.Name);
        Assert.AreEqual(NTIAErrorType.InvalidNTIAElement, invalidElement.ErrorType);
    }

    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingVerificationJsonString)]
    [DataRow(SbomFullDocWithFilesStrings.SbomFileWithMissingSHA256JsonString)]
    [TestMethod]
    public void MissingPropertiesTest_SPDX_NoVerificationCode_Passes(string jsonString)
    {
        var bytes = Encoding.UTF8.GetBytes(jsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);

        var result = this.Parse(parser);
        Assert.AreEqual(1, result.FilesCount);
    }

    [TestMethod]
    public void IgnoresAdditionalPropertiesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithFilesStrings.SbomFileWithAdditionalPropertiesJsonString);
        using var stream = new MemoryStream(bytes);
        var parser = new SPDX30Parser(stream);
        var result = this.Parse(parser);
        Assert.AreEqual(1, result.FilesCount);
    }
}
