using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
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
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();
        var count = 0;

        foreach (var file in parser.GetFiles(stream))
        {
            count++;
            Assert.IsNotNull(file);
        }

        Assert.AreEqual(2, count);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        new SbomFileParser(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public void StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();
        stream.Close();

        parser.GetFiles(stream).GetEnumerator().MoveNext(); 
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];
        
        TestParser parser = new ();

        parser.GetFiles(stream).GetEnumerator().MoveNext();
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

        TestParser parser = new (40);

        parser.GetFiles(stream).GetEnumerator().MoveNext();
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

        TestParser parser = new ();

        foreach (var file in parser.GetFiles(stream))
        {
            Assert.IsNotNull(file);
        }
    }

    [TestMethod]
    [ExpectedException(typeof(ParserError))]
    public void MalformedJsonTest_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();

        parser.GetFiles(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new(0);

        parser.GetFiles(stream).GetEnumerator().MoveNext();
    }
}
