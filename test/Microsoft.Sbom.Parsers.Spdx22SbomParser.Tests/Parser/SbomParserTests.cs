// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JsonStreaming;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomParserTests
{
    [TestMethod]
    public async Task ParseWithBOMTest()
    {
        var utf8BOM = Encoding.UTF8.GetString(Encoding.UTF8.Preamble);
        byte[] bytes = Encoding.UTF8.GetBytes(utf8BOM + SbomParserStrings.JsonWithAll4Properties);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(0, parser.FilesCount);

        Assert.AreEqual(0, parser.PackageCount);

        Assert.AreEqual(0, parser.RelationshipCount);

        Assert.AreEqual(0, parser.ReferenceCount);
    }

    [TestMethod]
    public async Task ParseMultiplePropertiesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithAll4Properties);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(0, parser.FilesCount);

        Assert.AreEqual(0, parser.PackageCount);

        Assert.AreEqual(0, parser.RelationshipCount);

        Assert.AreEqual(0, parser.ReferenceCount);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.JsonWithMissingFiles)]
    [DataRow(SbomParserStrings.JsonWithMissingPackages)]
    [DataRow(SbomParserStrings.JsonWithMissingRelationships)]
    [ExpectedException(typeof(ParserException))]
    public async Task MissingPropertyThrows(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        await IterateAllPropertiesAsync(stream);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJson)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRefsType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectFilesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectPackagesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRelationshipsType)]
    [ExpectedException(typeof(ParserException))]
    public async Task MalformedJsonThrows(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        await IterateAllPropertiesAsync(stream);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJsonEmptyJsonObject)]
    [DataRow(SbomParserStrings.MalformedJsonEmptyArrayObject)]
    public async Task MalformedJsonEmptyValuesDoesntThrow(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        await IterateAllPropertiesAsync(stream);
    }

    [TestMethod]
    public async Task MissingReferencesDoesntThrow()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithMissingReferences);
        using var stream = new MemoryStream(bytes);
        await IterateAllPropertiesAsync(stream);
    }

    private async Task IterateAllPropertiesAsync(Stream stream)
    {
        var parser = new TestSPDXParser(stream, requiredFields: true);
        await parser.ParseAsync(CancellationToken.None);
    }
}
