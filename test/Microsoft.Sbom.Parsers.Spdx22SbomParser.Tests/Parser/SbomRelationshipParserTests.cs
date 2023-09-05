// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
public class SbomRelationshipParserTests
{
    [TestMethod]
    public void ParseSbomRelationshipsTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
        using var stream = new MemoryStream(bytes);
        var count = 0;

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        foreach (var relationship in parser.GetRelationships())
        {
            count++;
            Assert.IsNotNull(relationship);
        }

        Assert.AreEqual(2, count);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        new SbomRelationshipParser(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public void StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        stream.Close();

        parser.GetRelationships().GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        parser.GetRelationships().GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingElementId)]
    [DataRow(RelationshipStrings.JsonRelationshipsStringMissingRelatedElement)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), 50);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        parser.GetRelationships().GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalString)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalObject)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArray)]
    [DataRow(RelationshipStrings.GoodJsonWithRelationshipsStringAdditionalArrayNoKey)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        foreach (var relationship in parser.GetRelationships())
        {
            Assert.IsNotNull(relationship);
        }
    }

    [DataTestMethod]
    [DataRow(RelationshipStrings.MalformedJsonRelationshipsStringBadRelationshipType)]
    [DataRow(RelationshipStrings.MalformedJsonRelationshipsString)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        parser.GetRelationships().GetEnumerator().MoveNext();
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        parser.GetRelationships().GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream, Array.Empty<ParserState>(), 0, ignoreValidation: true);

        var state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        parser.GetRelationships().GetEnumerator().MoveNext();
    }
}
