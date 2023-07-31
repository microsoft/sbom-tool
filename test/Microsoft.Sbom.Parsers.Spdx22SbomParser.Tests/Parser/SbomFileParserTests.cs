using System;
using System.IO;
using System.Text;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests
{
    [TestMethod]
    public void SkipSbomFiles_AfterNextFailsTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, ignoreValidation: true);
        while (parser.Next() != ParserState.FINISHED)
        {
            if (parser.CurrentState == ParserState.METADATA)
            {
                parser.GetMetadata();
                break;
            }
            else if (parser.CurrentState == ParserState.FILES)
            {
                parser.GetFiles();
                break;
            }
        }

        Assert.ThrowsException<InvalidOperationException>(() => parser.SkipStates(new[] { ParserState.FILES }));
    }

    [TestMethod]
    public void SkipSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, ignoreValidation: true);
        parser.SkipStates(new[] { ParserState.FILES });
        while (parser.Next() != ParserState.FINISHED)
        {
            if (parser.CurrentState == ParserState.METADATA)
            {
                break;
            }

            Assert.Fail("Never should have reached this point.");
        }
    }

    [TestMethod]
    public void ParseSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, ignoreValidation: true);

        var count = 0;

        while (parser.Next() != ParserState.FINISHED)
        {
            if (parser.CurrentState == ParserState.METADATA)
            {
                break;
            }

            Assert.AreEqual(ParserState.FILES, parser.CurrentState);

            foreach (var file in parser.GetFiles())
            {
                count++;
                Assert.IsNotNull(file);
            }
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

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        stream.Close();

        parser.GetFiles().GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        parser.GetFiles().GetEnumerator().MoveNext();
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
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        parser.GetFiles().GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalObjectPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalArrayPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalStringPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalValueArrayPropertyString)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        foreach (var file in parser.GetFiles())
        {
            Assert.IsNotNull(file);
        }
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.MalformedJson)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        parser.GetFiles().GetEnumerator().MoveNext();
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        parser.GetFiles().GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new(stream, 0, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        parser.GetFiles().GetEnumerator().MoveNext();
    }
}
