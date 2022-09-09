using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests
{
    private byte[] buffer = new byte[Constants.ReadBufferSize];

    [TestMethod]
    public void ParseSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        // var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);
        Console.WriteLine($"String in buffer is: {Encoding.UTF8.GetString(buffer)}");

        // Ensure first value is an array and read that so that we are the { token.
        var reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: default);
        ParserUtils.SkipNoneTokens(stream, ref buffer, ref reader);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.StartArray);
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.RemoveBytesRead(stream, ref buffer, ref reader);
        Console.WriteLine($"String in buffer is: {Encoding.UTF8.GetString(buffer)}");

        var parser1 = new SbomFileParser(stream, ref buffer, state: reader.CurrentState);
        var result = parser1.GetSbomFile(out SBOMFile sbomFile);
       
        Assert.IsTrue(result != 0);
        Assert.IsNotNull(sbomFile);

        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser1.CurrentState);

        Console.WriteLine($"String in buffer is: {Encoding.UTF8.GetString(buffer)}");

        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndObject);
        ParserUtils.Read(stream, ref buffer, ref reader);

        var parser2 = new SbomFileParser(stream, ref buffer, reader.CurrentState);
        result = parser2.GetSbomFile(out SBOMFile sbomFile2);

        Assert.IsTrue(result != 0);
        Assert.IsNotNull(sbomFile2);

        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser2.CurrentState);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndObject);
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.RemoveBytesRead(stream, ref buffer, ref reader);

        var parser3 = new SbomFileParser(stream, ref buffer, reader.CurrentState);
        result = parser3.GetSbomFile(out SBOMFile sbomFile3);

        Assert.IsTrue(result == 0);
        Assert.IsNull(sbomFile3);

        // We should be at the end of the array.
        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser3.CurrentState);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndArray);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullByteBufferThrows()
    {
        byte[] buffer = null;
        new SbomFileParser(new MemoryStream(), ref buffer);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        var buffer = new byte[2];
        new SbomFileParser(null, ref buffer);
    }

    [TestMethod]
    public void EmptyByteArrayReadsStreamToArrayBeforeStart()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];
        // Ensure first value is an array and read that so that we are the { token.
        var reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: default);
        ParserUtils.SkipNoneTokens(stream, ref buffer, ref reader);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.StartArray);
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.RemoveBytesRead(stream, ref buffer, ref reader);

        var parser1 = new SbomFileParser(stream, ref buffer, state: reader.CurrentState);
        var result = parser1.GetSbomFile(out SBOMFile sbomFile);

        Assert.IsTrue(result != 0);
        Assert.IsNotNull(sbomFile);

        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser1.CurrentState);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndObject);
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.RemoveBytesRead(stream, ref buffer, ref reader);

        var parser2 = new SbomFileParser(stream, ref buffer, reader.CurrentState);
        result = parser2.GetSbomFile(out SBOMFile sbomFile2);

        Assert.IsTrue(result != 0);
        Assert.IsNotNull(sbomFile2);

        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser2.CurrentState);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndObject);
        ParserUtils.Read(stream, ref buffer, ref reader);
        ParserUtils.RemoveBytesRead(stream, ref buffer, ref reader);

        var parser3 = new SbomFileParser(stream, ref buffer, reader.CurrentState);
        result = parser3.GetSbomFile(out SBOMFile sbomFile3);

        Assert.IsTrue(result == 0);
        Assert.IsNull(sbomFile3);

        // We should be at the end of the array.
        reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: parser3.CurrentState);
        ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.EndArray);
    }

    [TestMethod]
    public void StreamClosedTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Close();
        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(stream, ref buffer);
        var result = parser.GetSbomFile(out SBOMFile file);

        Assert.IsTrue(result == 0);
        Assert.IsNull(file);
    }

    [TestMethod]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(stream, ref buffer);
        var result = parser.GetSbomFile(out SBOMFile file);

        Assert.IsTrue(result == 0);
        Assert.IsNull(file);
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingNameString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingIDString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingChecksumsString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingSHA256ChecksumsString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingLicenseConcludedString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingLicenseInfoInFilesString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingCopyrightString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingCopyrightAndPathString)]
    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        var parser = new SbomFileParser(stream, ref buffer);
        parser.GetSbomFile(out SBOMFile _);

        // Shouldn't read last remaining ]
        Assert.IsTrue(Encoding.UTF8.GetString(new byte[] { buffer[0] }) == "]");
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalObjectPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalArrayPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalStringPropertyString)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        var parser = new SbomFileParser(stream, ref buffer);
        var result = parser.GetSbomFile(out SBOMFile sbomFile);

        Assert.IsTrue(result != 0);
        Assert.IsNotNull(sbomFile);

        // Shouldn't read last remaining ]
        Assert.IsTrue(Encoding.UTF8.GetString(new byte[] { buffer[0] }) == "]");
    }

    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void MalformedJsonTest_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new SbomFileParser(stream, ref buffer);
        parser.GetSbomFile(out SBOMFile _);
    }

    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void BadStateJsonTest_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var buffer = new byte[Constants.ReadBufferSize];
        var bufferCopy = new byte[Constants.ReadBufferSize];

        stream.Read(buffer);

        Array.Copy(buffer, bufferCopy, bufferCopy.Length);

        var reader = new Utf8JsonReader(buffer, isFinalBlock: false, state: default);

        while (reader.TokenType != JsonTokenType.String)
        {
            ParserUtils.Read(stream, ref buffer, ref reader);
        }

        var parser = new SbomFileParser(stream, ref buffer, reader.CurrentState);
        parser.GetSbomFile(out SBOMFile _);
    }
}
