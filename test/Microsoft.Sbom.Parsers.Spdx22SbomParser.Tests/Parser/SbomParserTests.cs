using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomParserTests
{
    [TestMethod]
    public void ParseMultiplePropertiesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithAll4Properties);
        using var stream = new MemoryStream(bytes);

        SPDXParser parser = new (stream);

        Assert.AreEqual(ParserState.NONE, parser.CurrentState);

        var state = parser.Next();
        Assert.AreEqual(ParserState.FILES, state);

        Assert.AreEqual(0, parser.GetFiles().Count());

        state = parser.Next();
        Assert.AreEqual(ParserState.PACKAGES, state);

        Assert.AreEqual(0, parser.GetPackages().Count());

        state = parser.Next();
        Assert.AreEqual(ParserState.RELATIONSHIPS, state);

        Assert.AreEqual(0, parser.GetRelationships().Count());

        state = parser.Next();
        Assert.AreEqual(ParserState.REFERENCES, state);

        Assert.AreEqual(0, parser.GetReferences().Count());

        state = parser.Next();
        Assert.AreEqual(ParserState.FINISHED, state);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.JsonWithMissingFiles)]
    [DataRow(SbomParserStrings.JsonWithMissingPackages)]
    [DataRow(SbomParserStrings.JsonWithMissingRelationships)]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertyThrows(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        IterateAllProperties(stream);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJson)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRefsType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectFilesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectPackagesType)]
    [DataRow(SbomParserStrings.MalformedJsonIncorrectRelationshipsType)]
    [ExpectedException(typeof(ParserException))]
    public void MalformedJsonThrows(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        IterateAllProperties(stream);
    }

    [DataTestMethod]
    [DataRow(SbomParserStrings.MalformedJsonEmptyJsonObject)]
    [DataRow(SbomParserStrings.MalformedJsonEmptyArrayObject)]
    public void MalformedJsonEmptyValuesDoesntThrow(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);
        IterateAllProperties(stream);
    }

    [TestMethod]
    public void MissingReferencesDoesntThrow()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithMissingReferences);
        using var stream = new MemoryStream(bytes);
        IterateAllProperties(stream);
    }

    private void IterateAllProperties(Stream stream)
    {
        SPDXParser parser = new (stream);
        while (parser.Next() != ParserState.FINISHED)
        {
            if (parser.CurrentState == ParserState.PACKAGES)
            {
                // Do nothing.
                parser.GetPackages().ToList();
            }

            if (parser.CurrentState == ParserState.FILES)
            {
                // Do nothing.
                parser.GetFiles().ToList();
            }

            if (parser.CurrentState == ParserState.REFERENCES)
            {
                // Do nothing.
                parser.GetReferences().ToList();
            }

            if (parser.CurrentState == ParserState.RELATIONSHIPS)
            {
                // Do nothing.
                parser.GetRelationships().ToList();
            }
        }
    }
}