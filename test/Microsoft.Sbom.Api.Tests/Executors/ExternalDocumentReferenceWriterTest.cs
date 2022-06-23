// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Executors
{
    [TestClass]
    public class ExternalDocumentReferenceWriterTest
    {
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
        private readonly Mock<IRecorder> recorderMock = new Mock<IRecorder>();
        private readonly Mock<IFileSystemUtils> fileSystemUtilsMock = new Mock<IFileSystemUtils>();

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

            ExternalDocumentReferenceInfo externalDocumentReferenceInfo = new ExternalDocumentReferenceInfo();
            externalDocumentReferenceInfo.ExternalDocumentName = "name";
            externalDocumentReferenceInfo.DocumentNamespace = "namespace";
            var checksum = new Checksum();
            checksum.Algorithm = AlgorithmName.SHA1;
            checksum.ChecksumValue = "abc";
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
                JsonElement root = result.Document.RootElement;

                Assert.IsNotNull(root);

                if (root.TryGetProperty("SpdxDocument", out JsonElement documentNamespace))
                {
                    Assert.AreEqual("namespace", documentNamespace.GetString());
                }
                else
                {
                    Assert.Fail("SpdxDocument property not found");
                }

                if (root.TryGetProperty("ExternalDocumentId", out JsonElement externalDocumentId))
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
}
