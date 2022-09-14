using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;

namespace Microsoft.Sbom.Parser
{
    [TestClass]
    public class SbomRelationshipParserTests
    {
        [TestMethod]
        public void ParseSbomRelationshipsTest()
        {
            byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
            using var stream = new MemoryStream(bytes);

            TestParser parser = new ();
            var count = 0;

            foreach (var relationship in parser.GetRelationships(stream))
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
            new SbomPackageParser(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ObjectDisposedException))]
        public void StreamClosedTestReturnsNull()
        {
            byte[] bytes = Encoding.UTF8.GetBytes(RelationshipStrings.GoodJsonWith2RelationshipsString);
            using var stream = new MemoryStream(bytes);

            TestParser parser = new ();
            stream.Close();

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
        }

        [TestMethod]
        [ExpectedException(typeof(EndOfStreamException))]
        public void StreamEmptyTestReturnsNull()
        {
            using var stream = new MemoryStream();
            stream.Read(new byte[Constants.ReadBufferSize]);
            var buffer = new byte[Constants.ReadBufferSize];

            TestParser parser = new ();

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
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

            TestParser parser = new (40);

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
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

            TestParser parser = new ();

            foreach (var package in parser.GetRelationships(stream))
            {
                Assert.IsNotNull(package);
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

            TestParser parser = new ();

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
        }

        [TestMethod]
        public void EmptyArray_ValidJson()
        {
            byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJsonEmptyArray);
            using var stream = new MemoryStream(bytes);

            TestParser parser = new ();

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NullOrEmptyBuffer_Throws()
        {
            byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
            using var stream = new MemoryStream(bytes);

            TestParser parser = new (0);

            parser.GetRelationships(stream).GetEnumerator().MoveNext();
        }
    }
}
