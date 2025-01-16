// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Executors;

[TestClass]
public class ExternalDocumentReferenceWriterTest
{
    private Mock<ILogger> mockLogger = new Mock<ILogger>();
    private Mock<IRecorder> recorderMock = new Mock<IRecorder>();
    private Mock<IFileSystemUtils> fileSystemUtilsMock = new Mock<IFileSystemUtils>();

    [TestMethod]
    public async Task PassExternalDocumentReferenceInfosChannel_ReturnsJsonDocWithSerializer()
    {
        var manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        manifestGeneratorProvider.Init();
        var metadataBuilder = new MetadataBuilder(
            mockLogger.Object,
            manifestGeneratorProvider,
            Constants.TestManifestInfo,
            recorderMock.Object);
        var jsonFilePath = "/root/_manifest/manifest.json";
        var sbomConfig = new SbomConfig(fileSystemUtilsMock.Object)
        {
            ManifestInfo = Constants.TestManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = jsonFilePath,
            MetadataBuilder = metadataBuilder,
            Recorder = new SbomPackageDetailsRecorder()
        };

        var externalDocumentReferenceInfo = new ExternalDocumentReferenceInfo
        {
            ExternalDocumentName = "name",
            DocumentNamespace = "namespace"
        };
        var checksum = new Checksum
        {
            Algorithm = AlgorithmName.SHA1,
            ChecksumValue = "abc"
        };
        externalDocumentReferenceInfo.Checksum = new List<Checksum> { checksum };

        var externalDocumentReferenceInfos = new List<ExternalDocumentReferenceInfo> { externalDocumentReferenceInfo };
        var externalDocumentReferenceInfosChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        foreach (var data in externalDocumentReferenceInfos)
        {
            await externalDocumentReferenceInfosChannel.Writer.WriteAsync(data);
        }

        externalDocumentReferenceInfosChannel.Writer.Complete();

        var externalDocumentReferenceWriter = new ExternalDocumentReferenceWriter(manifestGeneratorProvider, mockLogger.Object);
        var (results, errors) = externalDocumentReferenceWriter.Write(externalDocumentReferenceInfosChannel, new List<ISbomConfig> { sbomConfig });

        await foreach (var result in results.ReadAllAsync())
        {
            var root = result.Document.RootElement;

            if (root.TryGetProperty("Document", out var documentNamespace))
            {
                Assert.AreEqual("namespace", documentNamespace.GetString());
            }
            else
            {
                Assert.Fail("Document property not found");
            }

            if (root.TryGetProperty("ExternalDocumentId", out var externalDocumentId))
            {
                Assert.AreEqual("name", externalDocumentId.GetString());
            }
            else
            {
                Assert.Fail("ExternalDocumentId property not found");
            }
        }
    }
}
