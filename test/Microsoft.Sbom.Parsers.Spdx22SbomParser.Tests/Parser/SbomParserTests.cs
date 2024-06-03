// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Text;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomParserTests : SbomParserTestsBase
{
    [TestMethod]
    public void ParseWithBOMTest()
    {
        var utf8BOM = Encoding.UTF8.GetString(Encoding.UTF8.Preamble);
        var bytes = Encoding.UTF8.GetBytes(utf8BOM + SbomParserStrings.JsonWithAll4Properties);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(0, result.FilesCount);

        Assert.AreEqual(0, result.PackagesCount);

        Assert.AreEqual(0, result.RelationshipsCount);

        Assert.AreEqual(0, result.ReferencesCount);
    }

    [TestMethod]
    public void ParseMultiplePropertiesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithAll4Properties);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(0, result.FilesCount);

        Assert.AreEqual(0, result.PackagesCount);

        Assert.AreEqual(0, result.RelationshipsCount);

        Assert.AreEqual(0, result.ReferencesCount);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.JsonWithMissingFiles)]
    [DataRow(SbomParserStrings.JsonWithMissingPackages)]
    [DataRow(SbomParserStrings.JsonWithMissingRelationships)]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertyThrows(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        this.IterateAllPropertiesAsync(stream);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJson)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRefsType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectFilesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectPackagesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRelationshipsType)]
    public void MalformedJsonThrows(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        Assert.ThrowsException<ParserException>(() => this.IterateAllPropertiesAsync(stream));
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJsonEmptyJsonObject)]
    [DataRow(SbomParserStrings.MalformedJsonEmptyArrayObject)]
    public void MalformedJsonEmptyValuesDoesNotThrow(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        this.IterateAllPropertiesAsync(stream);
    }

    [TestMethod]
    public void MissingReferencesDoesNotThrow()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithMissingReferences);
        using var stream = new MemoryStream(bytes);
        this.IterateAllPropertiesAsync(stream);
    }

    private ParserResults IterateAllPropertiesAsync(Stream stream)
    {
        var parser = new SPDXParser(stream);
        return this.Parse(parser);
    }
}
