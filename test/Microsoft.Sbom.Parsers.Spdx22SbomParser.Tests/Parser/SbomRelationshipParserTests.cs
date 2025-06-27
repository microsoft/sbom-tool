// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SbomConstants = Microsoft.Sbom.Parsers.Spdx22SbomParser.Constants;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomRelationshipParserTests : SbomParserTestsBase
{
    [TestMethod]
    public void ParseSbomRelationshipsTest()
    {
        var bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(2, result.RelationshipsCount);
    }

    [TestMethod]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[SbomConstants.ReadBufferSize]);

        Assert.ThrowsException<EndOfStreamException>(() => new SPDXParser(stream));
    }

    [TestMethod]
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingElementId)]
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingRelatedElement)]
    public void MissingPropertiesTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream, bufferSize: 50);

        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalString)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalObject)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArray)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArrayNoKey)]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.IsTrue(result.RelationshipsCount > 0);
    }

    [TestMethod]
    [DataRow(RelationshipStrings.MalformedJsonRelationshipsString)]
    public void MalformedJsonTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        _ = Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        var bytes = Encoding.UTF8.GetBytes(RelationshipStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(0, result.RelationshipsCount);
    }

    [TestMethod]
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        Assert.ThrowsException<ArgumentException>(() => new SPDXParser(stream, bufferSize: 0));
    }
}
