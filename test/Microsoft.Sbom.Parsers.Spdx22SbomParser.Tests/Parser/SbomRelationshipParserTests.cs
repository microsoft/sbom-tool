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
public class SbomRelationshipParserTests
{
    [TestMethod]
    public async Task ParseSbomRelationshipsTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(2, parser.RelationshipCount);
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
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingElementId)]
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingRelatedElement)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public async Task MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream, bufferSize: 50);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalString)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalObject)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArray)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArrayNoKey)]
    [TestMethod]
    public async Task IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.IsTrue(parser.RelationshipCount > 0);
    }

    [DataTestMethod]
    [DataRow(RelationshipStrings.MalformedJsonRelationshipsStringBadRelationshipType)]
    [DataRow(RelationshipStrings.MalformedJsonRelationshipsString)]
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
        byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(0, parser.RelationshipCount);
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
