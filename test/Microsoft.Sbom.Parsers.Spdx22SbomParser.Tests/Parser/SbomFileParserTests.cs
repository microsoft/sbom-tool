// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JsonStreaming;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomFileParserTests
{
    [TestMethod]
    public async Task SkipSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);
        var skippedProperties = new[] { "files" };

        var parser = new TestSPDXParser(stream, skippedProperties: skippedProperties);

        await parser.ParseAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task ParseSbomFilesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(2, parser.FilesCount);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        _ = new TestSPDXParser(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public async Task StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.GoodJsonWith2FilesString);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream, block: true);

        var task = parser.ParseAsync(CancellationToken.None);

        stream.Close();

        await task;
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public async Task StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
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
    public async Task MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalObjectPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalArrayPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalStringPropertyString)]
    [DataRow(SbomFileJsonStrings.GoodJsonWith1FileAdditionalValueArrayPropertyString)]
    [TestMethod]
    public async Task IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(1, parser.FilesCount);
    }

    [DataTestMethod]
    [DataRow(SbomFileJsonStrings.MalformedJson)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public async Task MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(0, parser.FilesCount);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public async Task NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream, bufferSize: 0);

        await parser.ParseAsync(CancellationToken.None);
    }
}
