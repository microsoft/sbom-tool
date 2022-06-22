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
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using MoreLinq;
using Serilog;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Workflows.Helpers
{
    [TestClass]
    public class RelationshipsArrayGeneratorTest
    {
        private RelationshipsArrayGenerator relationshipsArrayGenerator;

        private readonly Mock<IRecorder> recorderMock = new Mock<IRecorder>();
        private readonly Mock<ISbomConfigProvider> sbomConfigsMock = new Mock<ISbomConfigProvider>();
        private readonly Mock<RelationshipGenerator> relationshipGeneratorMock = new Mock<RelationshipGenerator>(new ManifestGeneratorProvider(null));
        private readonly Mock<ILogger> loggerMock = new Mock<ILogger>();
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
        private readonly Mock<IFileSystemUtils> fileSystemUtilsMock = new Mock<IFileSystemUtils>();

        ManifestGeneratorProvider manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        ISbomPackageDetailsRecorder recorder;
        IMetadataBuilder metadataBuilder;
        ISbomConfig sbomConfig;
        ManifestInfo manifestInfo = new ManifestInfo();

        private const string documentId = "documentId";
        private const string rootPackageId = "rootPackageId";
        private const string fileId1 = "fileId1";
        private const string fileId2 = "fileId2";
        private InternalSBOMFileInfo file1 = new InternalSBOMFileInfo() { Path = fileId1 };
        private const string packageId1 = "packageId1";
        private const string externalDocRefId1 = "externalDocRefId1";
        private const string manifestJsonDirPath = "/root/_manifest";
        private const string jsonFilePath = "/root/_manifest/manifest.json";

        List<Relationship> relationships;

        [TestInitialize]
        public void Setup()
        {
            recorder = new SbomPackageDetailsRecorder();
            relationships = new List<Relationship>();
            relationshipGeneratorMock.Setup(r => r.Run(It.IsAny<IEnumerator<Relationship>>(), It.IsAny<ManifestInfo>()))
                .Callback<IEnumerator<Relationship>, ManifestInfo>((relationship, manifestInfo) =>
                {
                    while (relationship.MoveNext())
                    {
                        relationships.Add(relationship.Current);
                    }
                });
            relationshipGeneratorMock.CallBase = true;
            relationshipsArrayGenerator = new RelationshipsArrayGenerator()
            {
                ChannelUtils = new ChannelUtils(),
                Recorder = recorderMock.Object,
                Generator = relationshipGeneratorMock.Object,
                Log = loggerMock.Object,
                SbomConfigs = sbomConfigsMock.Object,
            };
            manifestGeneratorProvider.Init();
            metadataBuilder = new MetadataBuilder(
                mockLogger.Object,
                manifestGeneratorProvider,
                Constants.TestManifestInfo,
                recorderMock.Object);
            sbomConfig = new SbomConfig(fileSystemUtilsMock.Object)
            {
                ManifestInfo = Constants.TestManifestInfo,
                ManifestJsonDirPath = manifestJsonDirPath,
                ManifestJsonFilePath = jsonFilePath,
                MetadataBuilder = metadataBuilder,
                Recorder = recorder,
            };
            fileSystemUtilsMock.Setup(f => f.CreateDirectory(manifestJsonDirPath));
            fileSystemUtilsMock.Setup(f => f.OpenWrite(jsonFilePath)).Returns(new MemoryStream());

            sbomConfig.StartJsonSerialization();
            sbomConfig.JsonSerializer.StartJsonObject();

            sbomConfigsMock.Setup(s => s.GetManifestInfos()).Returns(new List<ManifestInfo> { manifestInfo });
            sbomConfigsMock.Setup(s => s.Get(manifestInfo)).Returns(sbomConfig);
        }

        [TestMethod]
        public async Task When_BaseGenerationDataExist_DescribesRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(documentId);
            recorder.RecordRootPackageId(rootPackageId);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(1, relationships.Count);

            var describesRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DESCRIBES);
            Assert.AreEqual(1, describesRelationships.Count());
            var describesRelationship = describesRelationships.First();
            Assert.AreEqual(rootPackageId, describesRelationship.TargetElementId);
            Assert.AreEqual(documentId, describesRelationship.SourceElementId);
        }

        [TestMethod]
        public async Task When_SPDXFileGenerationDataExist_DescribedByRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(documentId);
            recorder.RecordRootPackageId(rootPackageId);
            recorder.RecordFileId(fileId1);
            recorder.RecordFileId(fileId2);
            recorder.RecordSPDXFileId(fileId1);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var describedByRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DESCRIBED_BY);
            Assert.AreEqual(1, describedByRelationships.Count());
            var describedByRelationship = describedByRelationships.First();
            Assert.AreEqual(documentId, describedByRelationship.TargetElementId);
            Assert.AreEqual(fileId1, describedByRelationship.SourceElementId);
        }

        [TestMethod]
        public async Task When_ExternalDocRefGenerationDataExist_PreReqRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(documentId);
            recorder.RecordRootPackageId(rootPackageId);
            recorder.RecordExternalDocumentReferenceIdAndRootElement(externalDocRefId1, rootPackageId);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var preReqForRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.PREREQUISITE_FOR);
            Assert.AreEqual(1, preReqForRelationships.Count());
            var preReqForRelationship = preReqForRelationships.First();
            Assert.AreEqual(rootPackageId, preReqForRelationship.TargetElementId);
            Assert.AreEqual(rootPackageId, preReqForRelationship.SourceElementId);
            Assert.AreEqual(externalDocRefId1, preReqForRelationship.TargetElementExternalReferenceId);
        }

        [TestMethod]
        public async Task When_PackageGenerationDataExist_DependOnRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(documentId);
            recorder.RecordRootPackageId(rootPackageId);
            recorder.RecordPackageId(packageId1);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var dependsOnRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DEPENDS_ON);
            Assert.AreEqual(1, dependsOnRelationships.Count());
            var dependsOnRelationship = dependsOnRelationships.First();
            Assert.AreEqual(packageId1, dependsOnRelationship.TargetElementId);
            Assert.AreEqual(rootPackageId, dependsOnRelationship.SourceElementId);
        }

        [TestMethod]
        public async Task When_NoGenerationDataExist_NoRelationshipsAreGenerated()
        {
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(0, relationships.Count);
        }
    }
}
