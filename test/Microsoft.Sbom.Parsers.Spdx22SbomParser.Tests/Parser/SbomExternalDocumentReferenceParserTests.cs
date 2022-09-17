using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomExternalDocumentReferenceParserTests
{
    [TestMethod]
    public void ParseSbomExternalDocumentReferenceTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(ExternalDocumentReferenceStrings.GoodJsonWith2ExtDocumentRefsString);
        using var stream = new MemoryStream(bytes);
        var count = 0;

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        foreach (var extReference in parser.GetReferences(stream))
        {
            count++;
            Assert.IsNotNull(extReference);
        }

        Assert.AreEqual(2, count);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        new SbomExternalDocumentReferenceParser(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public void StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(ExternalDocumentReferenceStrings.GoodJsonWith2ExtDocumentRefsString);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);
        stream.Close();

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingChecksum)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingDocumentId)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingDocument)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingSHA1Checksum)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringAdditionalObject)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringAdditionalString)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringAdditionalArray)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringAdditionalArrayNoKey)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        foreach (var package in parser.GetReferences(stream))
        {
            Assert.IsNotNull(package);
        }
    }

    [DataTestMethod]
    [DataRow(ExternalDocumentReferenceStrings.MalformedJson)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new ();

        var state = parser.Next(stream);
        Assert.AreEqual(ParserState.REFERENCES, state);

        parser.GetReferences(stream).GetEnumerator().MoveNext();
    }
}
