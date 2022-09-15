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
    public void ParseSbomRelationshipsTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(ExternalDocumentReferenceStrings.GoodJsonWith2ExtDocumentRefsString);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();
        var count = 0;

        foreach (var externalDocumentReference in parser.GetExternalDocumentReferences(stream))
        {
            count++;
            Assert.IsNotNull(externalDocumentReference);
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

        TestParser parser = new ();
        stream.Close();

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        TestParser parser = new ();

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingChecksum)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingSHA1Checksum)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingDocument)]
    [DataRow(ExternalDocumentReferenceStrings.JsonExtDocumentRefsStringMissingDocumentId)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new (40);

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
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

        TestParser parser = new ();

        foreach (var package in parser.GetExternalDocumentReferences(stream))
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

        TestParser parser = new ();

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new (0);

        parser.GetExternalDocumentReferences(stream).GetEnumerator().MoveNext();
    }
}
