// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Text;
using JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests : SbomParserTestsBase
{
    [TestMethod]
    public void SkipSbomFilesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);
        var skippedProperties = new[] { "files" };

        var parser = new SPDXParser(stream, skippedProperties: skippedProperties);

        var results = this.Parse(parser);
        Assert.IsNull(results.FilesCount);
    }

    [TestMethod]
    public void ParseSbomFilesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var results = this.Parse(parser);

        Assert.AreEqual(2, results.FilesCount);
    }

    [TestMethod]
    public void NullStreamThrows()
    {
        _ = Assert.ThrowsException<ArgumentNullException>(() => new SPDXParser(null));
    }

    [TestMethod]
    public void StreamClosedTestReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        Assert.ThrowsException<ObjectDisposedException>(() => this.Parse(parser, stream, close: true));
    }

    [TestMethod]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        Assert.ThrowsException<EndOfStreamException>(() => new SPDXParser(stream));
    }

    [TestMethod]
    public void MissingPropertiesTest_ThrowsSHA256()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.JsonWith1FileMissingSHA256ChecksumsString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);
        Assert.IsNotNull(result);

        Assert.ThrowsException<ParserException>(() => result.Files.Select(f => f.ToSbomFile()).ToList());
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingNameString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingIDString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingChecksumsString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingLicenseConcludedString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingLicenseInfoInFilesString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingCopyrightString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingCopyrightAndPathString)]
    [TestMethod]
    public void MissingPropertiesTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        _ = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalObjectPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalArrayPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalStringPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalValueArrayPropertyString)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(1, result.FilesCount);
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.MalformedJson)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    public void MalformedJsonTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(0, result.FilesCount);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream, bufferSize: 0);
        Assert.ThrowsException<ArgumentException>(() => this.Parse(parser));
    }
}
