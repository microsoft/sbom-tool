using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests
{
    [TestMethod]
    public void ParseSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonStrings.GoodJsonWith3FilesString);
        var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        var parser = new SbomFileParser(buffer, stream);
        var result = parser.GetSbomFile(out SBOMFile sbomFile);

        Assert.IsTrue(result);
        Assert.IsNotNull(sbomFile);

        result = parser.GetSbomFile(out SBOMFile sbomFile2);

        Assert.IsTrue(result);
        Assert.IsNotNull(sbomFile2);

        result = parser.GetSbomFile(out SBOMFile sbomFile3);

        Assert.IsFalse(result);
        Assert.IsNull(sbomFile3);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullByteBufferThrows()
    {
        new SbomFileParser(null, new MemoryStream());
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        new SbomFileParser(new byte[3], null);
    }

    [TestMethod]
    public void EmptyByteArrayReadsStreamToArrayBeforeStart()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonStrings.GoodJsonWith3FilesString);
        var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(buffer, stream);
        var result = parser.GetSbomFile(out SBOMFile sbomFile);

        Assert.IsTrue(result);
        Assert.IsNotNull(sbomFile);

        result = parser.GetSbomFile(out SBOMFile sbomFile2);

        Assert.IsTrue(result);
        Assert.IsNotNull(sbomFile2);

        result = parser.GetSbomFile(out SBOMFile sbomFile3);

        Assert.IsFalse(result);
        Assert.IsNull(sbomFile3);
    }

    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void StreamClosedTest_Throws()
    {
        var stream = new MemoryStream();
        stream.Close();
        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(buffer, stream);
        parser.GetSbomFile(out SBOMFile _);
    }

    [DataTestMethod]
    [DataRow(JsonStrings.JsonWith1FileMissingNameString)]
    [DataRow(JsonStrings.JsonWith1FileMissingIDString)]
    [DataRow(JsonStrings.JsonWith1FileMissingChecksumsString)]
    [DataRow(JsonStrings.JsonWith1FileMissingSHA256ChecksumsString)]
    [DataRow(JsonStrings.JsonWith1FileMissingLicenseConcludedString)]
    [DataRow(JsonStrings.JsonWith1FileMissingLicenseInfoInFilesString)]
    [DataRow(JsonStrings.JsonWith1FileMissingCopyrightString)]
    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        var parser = new SbomFileParser(buffer, stream);
        parser.GetSbomFile(out SBOMFile _);
    }

    [TestMethod]
    public void IgnoresAdditionalPropertiesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonStrings.GoodJsonWith1FileAdditionalPropertiesString);
        var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        var parser = new SbomFileParser(buffer, stream);
        var result = parser.GetSbomFile(out SBOMFile sbomFile);

        Assert.IsTrue(result);
        Assert.IsNotNull(sbomFile);
    }

    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void MalformedJsonTest_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonStrings.MalformedJson);
        var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(buffer, stream);
        parser.GetSbomFile(out SBOMFile _);
    }
}
