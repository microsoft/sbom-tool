// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
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
    public void MetadataPopulates()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var results = this.Parse(parser);
        var metadata = parser.GetMetadata();

        Assert.IsNotNull(metadata);
        Assert.IsInstanceOfType(metadata, typeof(Spdx22Metadata));
        Assert.IsNotNull(metadata.CreationInfo);
        var expectedTime = DateTime.Parse("2023-05-11T00:24:54Z").ToUniversalTime();
        Assert.AreEqual(expectedTime, metadata.CreationInfo.Created);
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
    public void MissingPropertiesTest_AcceptsWithoutSHA256()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.JsonWith1FileMissingSHA256ChecksumsString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);
        Assert.IsNotNull(result);

        var files = result.Files.Select(f => f.ToSbomFile()).ToList();
        Assert.AreEqual(1, files.Count);
        Assert.AreEqual(1, files[0].Checksum.Count());
        Assert.AreEqual(Contracts.Enums.AlgorithmName.SHA1, files[0].Checksum.Single().Algorithm);
    }

    [TestMethod]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingNameString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingIDString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingChecksumsString)]
    [DataRow(SbomFileJsonStrings.JsonWith1FileMissingCopyrightAndPathString)]
    public void MissingPropertiesTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        _ = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalObjectPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalArrayPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalStringPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalValueArrayPropertyString)]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(1, result.FilesCount);
    }

    [TestMethod]
    [DataRow(SbomFileJsonStrings.MalformedJson)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObjectNoArrayEnd)]
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
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        Assert.ThrowsException<ArgumentException>(() => new SPDXParser(stream, bufferSize: 0));
    }
}
