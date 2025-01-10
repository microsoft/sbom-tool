// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.JsonStrings;
using Microsoft.Sbom.Parsers.Spdx30SbomParser;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomMetadataParserTests : SbomParserTestsBase
{
    [TestMethod]
    public void MetadataPopulates()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithValidMetadataJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);

        var results = this.Parse(parser);
        Assert.IsTrue(results.FormatEnforcedSPDX3Result.Graph.Count() == 5);

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
        Assert.IsTrue(metadata.DocumentNamespace != null);
        Assert.IsTrue(metadata.Name == "spdx-doc-name");
        Assert.IsTrue(metadata.SpdxId == "SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1");
        Assert.IsTrue(metadata.DocumentDescribes.First() == "root-element-example");
        Assert.IsTrue(metadata.DataLicense == "CC0-1.0");
        Assert.IsTrue(metadata.CreationInfo.Creators.Count() == 2);
        Assert.IsTrue(metadata.CreationInfo.Created != DateTime.MinValue);
        Assert.IsTrue(metadata.SpdxVersion == "3.0");
    }

    [TestMethod]
    public void MetadataEmpty()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);

        var results = this.Parse(parser);

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
        Assert.IsTrue(metadata.DocumentNamespace == null);
        Assert.IsTrue(metadata.Name == null);
        Assert.IsTrue(metadata.SpdxId == null);
        Assert.IsTrue(metadata.DocumentDescribes == null);
        Assert.IsTrue(metadata.DataLicense == null);
        Assert.IsTrue(metadata.CreationInfo == null);
        Assert.IsTrue(metadata.SpdxVersion == null);
    }

    [TestMethod]
    public void DocCreation_NoName_NTIA_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithSpdxDocumentMissingNameJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream, requiredComplianceStandard: "NTIA");
        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void DocCreation_NoName_Passes()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithSpdxDocumentMissingNameJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        var results = this.Parse(parser);
        Assert.IsTrue(results.FormatEnforcedSPDX3Result.Graph.Count() == 5);

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
    }

    [TestMethod]
    public void InvalidContextThrows()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithInvalidContextJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void NullStreamThrows()
    {
        _ = Assert.ThrowsException<ArgumentNullException>(() => new SPDXParser(null));
    }

    [TestMethod]
    public void StreamClosedTestReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithValidMetadataJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);

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

    [DataTestMethod]
    [DataRow(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyArray)]
    [TestMethod]
    public void MalformedJsonTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(0, result.FilesCount);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyObject);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream, bufferSize: 0);
        this.Parse(parser);
        Assert.ThrowsException<ArgumentException>(() => this.Parse(parser));
    }
}
