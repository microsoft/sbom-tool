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
        private readonly ManifestGeneratorProvider manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        private ISbomPackageDetailsRecorder recorder;
        private IMetadataBuilder metadataBuilder;
        private ISbomConfig sbomConfig;
        private readonly ManifestInfo manifestInfo = new ManifestInfo();

        private const string DocumentId = "documentId";
        private const string RootPackageId = "rootPackageId";
        private const string FileId1 = "fileId1";
        private const string FileId2 = "fileId2";
        private const string PackageId1 = "packageId1";
        private const string ExternalDocRefId1 = "externalDocRefId1";
        private const string ManifestJsonDirPath = "/root/_manifest";
        private const string JsonFilePath = "/root/_manifest/manifest.json";

        private List<Relationship> relationships;

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
            relationshipsArrayGenerator = new RelationshipsArrayGenerator(relationshipGeneratorMock.Object, new ChannelUtils(), loggerMock.Object, sbomConfigsMock.Object, recorderMock.Object);
            manifestGeneratorProvider.Init();
            metadataBuilder = new MetadataBuilder(
                mockLogger.Object,
                manifestGeneratorProvider,
                Constants.TestManifestInfo,
                recorderMock.Object);
            sbomConfig = new SbomConfig(fileSystemUtilsMock.Object)
            {
                ManifestInfo = Constants.TestManifestInfo,
                ManifestJsonDirPath = ManifestJsonDirPath,
                ManifestJsonFilePath = JsonFilePath,
                MetadataBuilder = metadataBuilder,
                Recorder = recorder,
            };
            fileSystemUtilsMock.Setup(f => f.CreateDirectory(ManifestJsonDirPath));
            fileSystemUtilsMock.Setup(f => f.OpenWrite(JsonFilePath)).Returns(new MemoryStream());

            sbomConfig.StartJsonSerialization();
            sbomConfig.JsonSerializer.StartJsonObject();

            sbomConfigsMock.Setup(s => s.GetManifestInfos()).Returns(new List<ManifestInfo> { manifestInfo });
            sbomConfigsMock.Setup(s => s.Get(manifestInfo)).Returns(sbomConfig);
        }

        [TestMethod]
        public async Task When_BaseGenerationDataExist_DescribesRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(DocumentId);
            recorder.RecordRootPackageId(RootPackageId);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(1, relationships.Count);

            var describesRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DESCRIBES);
            Assert.AreEqual(1, describesRelationships.Count());
            var describesRelationship = describesRelationships.First();
            Assert.AreEqual(RootPackageId, describesRelationship.TargetElementId);
            Assert.AreEqual(DocumentId, describesRelationship.SourceElementId);
        }

        [TestMethod]
        public async Task When_SPDXFileGenerationDataExist_DescribedByRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(DocumentId);
            recorder.RecordRootPackageId(RootPackageId);
            recorder.RecordFileId(FileId1);
            recorder.RecordFileId(FileId2);
            recorder.RecordSPDXFileId(FileId1);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var describedByRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DESCRIBED_BY);
            Assert.AreEqual(1, describedByRelationships.Count());
            var describedByRelationship = describedByRelationships.First();
            Assert.AreEqual(DocumentId, describedByRelationship.TargetElementId);
            Assert.AreEqual(FileId1, describedByRelationship.SourceElementId);
        }

        [TestMethod]
        public async Task When_ExternalDocRefGenerationDataExist_PreReqRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(DocumentId);
            recorder.RecordRootPackageId(RootPackageId);
            recorder.RecordExternalDocumentReferenceIdAndRootElement(ExternalDocRefId1, RootPackageId);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var preReqForRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.PREREQUISITE_FOR);
            Assert.AreEqual(1, preReqForRelationships.Count());
            var preReqForRelationship = preReqForRelationships.First();
            Assert.AreEqual(RootPackageId, preReqForRelationship.TargetElementId);
            Assert.AreEqual(RootPackageId, preReqForRelationship.SourceElementId);
            Assert.AreEqual(ExternalDocRefId1, preReqForRelationship.TargetElementExternalReferenceId);
        }

        [TestMethod]
        public async Task When_PackageGenerationDataExist_DependOnRelationshipsAreGenerated()
        {
            recorder.RecordDocumentId(DocumentId);
            recorder.RecordRootPackageId(RootPackageId);
            recorder.RecordPackageId(PackageId1);
            var results = await relationshipsArrayGenerator.GenerateAsync();

            Assert.AreEqual(0, results.Count);
            Assert.AreEqual(2, relationships.Count);

            var dependsOnRelationships = relationships.Where(r => r.RelationshipType == RelationshipType.DEPENDS_ON);
            Assert.AreEqual(1, dependsOnRelationships.Count());
            var dependsOnRelationship = dependsOnRelationships.First();
            Assert.AreEqual(PackageId1, dependsOnRelationship.TargetElementId);
            Assert.AreEqual(RootPackageId, dependsOnRelationship.SourceElementId);
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
