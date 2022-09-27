using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Parser
{
    [TestClass]
    public class SbomParserTests
    {
        [TestMethod]
        public void ParseMultiplePropertiesTest()
        {
            byte[] bytes = Encoding.UTF8.GetBytes(SbomParserStrings.JsonWithAll4Properties);
            using var stream = new MemoryStream(bytes);

            SPDXParser parser = new ();

            Assert.AreEqual(ParserState.NONE, parser.CurrentState);

            var state = parser.Next(stream);
            Assert.AreEqual(ParserState.FILES, state);

            Assert.AreEqual(0, parser.GetFiles(stream).Count());

            state = parser.Next(stream);
            Assert.AreEqual(ParserState.PACKAGES, state);

            Assert.AreEqual(0, parser.GetPackages(stream).Count());

            state = parser.Next(stream);
            Assert.AreEqual(ParserState.RELATIONSHIPS, state);

            Assert.AreEqual(0, parser.GetRelationships(stream).Count());

            state = parser.Next(stream);
            Assert.AreEqual(ParserState.REFERENCES, state);

            Assert.AreEqual(0, parser.GetReferences(stream).Count());

            state = parser.Next(stream);
        }
    }
}
