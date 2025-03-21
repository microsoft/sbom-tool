// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.JsonStrings;
using Microsoft.Sbom.Parsers.Spdx30SbomParser;
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
        Assert.AreEqual(5, results.FormatEnforcedSPDX3Result.Graph.Count());

        var metadata = parser.GetMetadata();
        Assert.IsInstanceOfType(metadata, typeof(SpdxMetadata));
        Assert.IsNotNull(metadata);
        Assert.IsNotNull(metadata.DocumentNamespace);
        Assert.AreEqual("spdx-doc-name", metadata.Name);
        Assert.AreEqual("SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1", metadata.SpdxId);
        Assert.AreEqual("root-element-example", metadata.DocumentDescribes.First());
        Assert.AreEqual("CC0-1.0", metadata.DataLicense);
        Assert.AreEqual(2, metadata.CreationInfo.Creators.Count());
        Assert.AreNotEqual(DateTime.MinValue, metadata.CreationInfo.Created);
        Assert.AreEqual("3.0", metadata.SpdxVersion);
    }

    [TestMethod]
    public void MetadataEmpty()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.JsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);

        var results = this.Parse(parser);

        var metadata = parser.GetMetadata();
        Assert.IsInstanceOfType(metadata, typeof(SpdxMetadata));
        Assert.IsNotNull(metadata);
        Assert.IsNull(metadata.DocumentNamespace);
        Assert.IsNull(metadata.Name);
        Assert.IsNull(metadata.SpdxId);
        Assert.IsNull(metadata.DocumentDescribes);
        Assert.IsNull(metadata.DataLicense);
        Assert.IsNull(metadata.CreationInfo);
        Assert.IsNull(metadata.SpdxVersion);
    }

    [TestMethod]
    public void DocCreation_NoName_Passes()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithSpdxDocumentMissingNameJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        var results = this.Parse(parser);
        Assert.AreEqual(5, results.FormatEnforcedSPDX3Result.Graph.Count());

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
    }

    [TestMethod]
    public void DocCreation_NoName_NTIA_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithSpdxDocumentMissingNameJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(2, results.InvalidComplianceStandardElements.Count);
        Assert.IsTrue(results.InvalidComplianceStandardElements.Contains("SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"));
        Assert.IsTrue(results.InvalidComplianceStandardElements.Contains("missingValidSpdxDocument"));
    }

    [TestMethod]
    public void DocCreation_MultipleSpdxDocuments_NTIA_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithMultipleSpdxDocumentsJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(2, results.InvalidComplianceStandardElements.Count);
        Assert.IsTrue(results.InvalidComplianceStandardElements.Contains("additionalSpdxDocumentWithSpdxId: \"SPDXRef-SpdxDocument-A93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1\""));
        Assert.IsTrue(results.InvalidComplianceStandardElements.Contains("additionalSpdxDocumentWithSpdxId: \"SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1\""));
    }

    [TestMethod]
    public void DocCreation_MultipleSpdxDocuments_Passes()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithMultipleSpdxDocumentsJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(6, results.FormatEnforcedSPDX3Result.Graph.Count());

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
    }

    [DataRow(SbomFullDocWithMetadataJsonStrings.SbomWithMissingValidCreationInfoJsonString)]
    [DataRow(SbomFullDocWithMetadataJsonStrings.SbomWithMissingCreationInfoJsonString)]
    [TestMethod]
    public void DocCreation_InvalidCreationInfo_NTIA_Throws(string jsonString)
    {
        var bytes = Encoding.UTF8.GetBytes(jsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(1, results.InvalidComplianceStandardElements.Count);
        Assert.IsTrue(results.InvalidComplianceStandardElements.Contains("missingValidCreationInfoWithId: \"_:creationinfo\""));
    }

    [TestMethod]
    public void DocCreation_InvalidCreationInfo_Passes()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithMissingValidCreationInfoJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(5, results.FormatEnforcedSPDX3Result.Graph.Count());

        var metadata = parser.GetMetadata();
        Assert.IsNotNull(metadata);
    }

    [TestMethod]
    public void DocCreation_MissingCreationInfo_Passes()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.SbomWithMissingCreationInfoJsonString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDX30Parser(stream);
        parser.SetComplianceStandard("NTIA");
        var results = this.Parse(parser);
        Assert.AreEqual(4, results.FormatEnforcedSPDX3Result.Graph.Count());

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

    [TestMethod]
    [DataRow(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyArray)]
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
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFullDocWithMetadataJsonStrings.MalformedJsonEmptyObject);
        using var stream = new MemoryStream(bytes);

        Assert.ThrowsException<ArgumentException>(() => new SPDX30Parser(stream, bufferSize: 0));
    }
}
