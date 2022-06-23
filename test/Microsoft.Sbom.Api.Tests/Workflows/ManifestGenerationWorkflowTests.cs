// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders;
using Microsoft.Sbom.Api.Providers.FilesProviders;
using Microsoft.Sbom.Api.Providers.PackagesProviders;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json.Linq;
using Serilog.Events;
using Checksum = Microsoft.Sbom.Contracts.Checksum;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Workflows.Tests
{
    [TestClass]
    public class ManifestGenerationWorkflowTests
    {
        private readonly Mock<IRecorder> recorderMock = new Mock<IRecorder>();

        private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>();
        private readonly Mock<IConfiguration> configurationMock = new Mock<IConfiguration>();
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
        private readonly Mock<IHashCodeGenerator> hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        private readonly Mock<IOSUtils> mockOSUtils = new Mock<IOSUtils>();
        private readonly Mock<IManifestConfigHandler> mockConfigHandler = new Mock<IManifestConfigHandler>();
        private readonly Mock<IMetadataProvider> mockMetadataProvider = new Mock<IMetadataProvider>();
        private readonly Mock<ComponentDetectorCachedExecutor> mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<ComponentDetector>().Object);
        private readonly Mock<IJsonArrayGenerator> relationshipArrayGenerator = new Mock<IJsonArrayGenerator>();
        private readonly Mock<ComponentToPackageInfoConverter> packageInfoConverterMock = new Mock<ComponentToPackageInfoConverter>();
        private readonly Mock<ISBOMReaderForExternalDocumentReference> sBOMReaderForExternalDocumentReferenceMock = new Mock<ISBOMReaderForExternalDocumentReference>();
        private readonly Mock<IFileSystemUtilsExtension> fileSystemUtilsExtensionMock = new Mock<IFileSystemUtilsExtension>();

        [TestInitialize]
        public void Setup()
        {
            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));
            fileSystemUtilsExtensionMock.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        }

        [TestMethod]
        [DataRow(true, true)]
        [DataRow(false, false)]
        [DataRow(true, false)]
        [DataRow(false, true)]
        public async Task ManifestGenerationWorkflowTests_Succeeds(bool deleteExistingManifestDir, bool isDefaultSourceManifestDirPath)
        {
            var manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
            manifestGeneratorProvider.Init();

            var metadataBuilder = new MetadataBuilder(
               mockLogger.Object,
               manifestGeneratorProvider,
               Constants.TestManifestInfo,
               recorderMock.Object);
            var jsonFilePath = "/root/_manifest/manifest.json";

            ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
            {
                ManifestInfo = Constants.TestManifestInfo,
                ManifestJsonDirPath = "/root/_manifest",
                ManifestJsonFilePath = jsonFilePath,
                MetadataBuilder = metadataBuilder,
                Recorder = new SbomPackageDetailsRecorder()
            };

            mockConfigHandler.Setup(c => c.TryGetManifestConfig(out sbomConfig)).Returns(true);
            mockMetadataProvider.SetupGet(m => m.MetadataDictionary).Returns(new Dictionary<MetadataKey, object>
            {
                { MetadataKey.Build_BuildId, 12 },
                { MetadataKey.Build_DefinitionName, "test" },
            });

            var sbomConfigs = new SbomConfigProvider(
                new IManifestConfigHandler[] { mockConfigHandler.Object },
                new IMetadataProvider[] { mockMetadataProvider.Object },
                mockLogger.Object,
                recorderMock.Object);

            using var manifestStream = new MemoryStream();
            using var manifestWriter = new StreamWriter(manifestStream);
            using var sha256Stream = new MemoryStream();
            using var sha256Writer = new StreamWriter(sha256Stream);

            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            if (isDefaultSourceManifestDirPath)
            {
                configurationMock.SetupGet(c => c.ManifestDirPath)
                    .Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
                fileSystemMock.Setup(f => f.DirectoryExists(It.Is<string>(d => d == PathUtils.Join("/root", "_manifest"))))
                    .Returns(deleteExistingManifestDir);

                if (deleteExistingManifestDir)
                {
                    mockOSUtils.Setup(o => o.GetEnvironmentVariable(It.IsAny<string>())).Returns("true");
                    fileSystemMock.Setup(f => f.DeleteDir(It.IsAny<string>(), true)).Verifiable();
                }
            }
            else
            {
                configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest"), Source = SettingSource.CommandLine });
            }

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Generate);
            configurationMock.SetupGet(c => c.Verbosity).Returns(new ConfigurationSetting<LogEventLevel> { Value = LogEventLevel.Information });
            configurationMock.SetupGet(c => c.BuildComponentPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            fileSystemMock
                .Setup(f => f.CreateDirectory(
                    It.Is<string>(d => d == "/root/_manifest")))
                .Returns(new DirectoryInfo("/"));
            fileSystemMock
                .Setup(f => f.OpenWrite(
                    It.Is<string>(d => d == "/root/_manifest/manifest.json")))
                .Returns(manifestWriter.BaseStream);

            fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "/root"), true)).Returns(new string[] { "child1", "child2", "child3", "_manifest" });
            fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "child1"), true)).Returns(new string[] { });
            fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "child2"), true)).Returns(new string[] { "grandchild1", "grandchild2" });

            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child1"), true)).Returns(new string[] { "/root/child1/file1", "/root/child1/file2" });
            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child2"), true)).Returns(new string[] { "/root/child2/file3", "/root/child2/file4", "/root/child2/file5" });
            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child3"), true)).Returns(new string[] { "/root/child3/file11", "/root/child3/file12" });
            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "_manifest"), true)).Returns(new string[] { "/root/_manifest/manifest.json", "/root/_manifest/manifest.cat" });

            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "grandchild1"), true)).Returns(new string[] { "/root/child2/grandchild1/file6", "/root/child2/grandchild1/file10" });
            fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "grandchild2"), true)).Returns(new string[] { "/root/child2/grandchild1/file7", "/root/child2/grandchild1/file9" });

            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            fileSystemMock.Setup(f => f.FileExists(It.Is<string>(c => c == jsonFilePath))).Returns(true);
            fileSystemMock.Setup(f => f.OpenRead(It.Is<string>(c => c == jsonFilePath))).Returns(TestUtils.GenerateStreamFromString("randomContent"));
            fileSystemMock.Setup(f => f.OpenWrite(It.Is<string>(c => c == "/root/_manifest/manifest.json.sha256"))).Returns(sha256Writer.BaseStream);

            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()))
                                .Returns((string fileName, AlgorithmName[] algos) =>
                                            algos.Select(a =>
                                                new Checksum
                                                {
                                                    ChecksumValue = $"{fileName}hash",
                                                    Algorithm = a
                                                })
                                            .ToArray());

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();

            var scannedComponents = new List<ScannedComponent>();
            for (int i = 1; i < 4; i++)
            {
                var scannedComponent = new ScannedComponent
                {
                    Component = new NpmComponent("componentName", $"{i}")
                };

                scannedComponents.Add(scannedComponent);
            }

            var scanResult = new ScanResult
            {
                ResultCode = ProcessingResultCode.Success,
                ComponentsFound = scannedComponents
            };

            mockDetector.Setup(o => o.Scan(It.IsAny<string[]>())).Returns(scanResult);

            var packagesChannel = Channel.CreateUnbounded<SBOMPackage>();
            var errorsChannel = Channel.CreateUnbounded<FileValidationResult>();
            foreach (var component in scannedComponents)
            {
                await packagesChannel.Writer.WriteAsync(new SBOMPackage { PackageName = component.GetHashCode().ToString() });
            }

            packagesChannel.Writer.Complete();
            errorsChannel.Writer.Complete();
            packageInfoConverterMock
                .Setup(p => p.Convert(It.IsAny<ChannelReader<ScannedComponent>>()))
                .Returns((packagesChannel, errorsChannel));

            var externalDocumentReferenceChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
            var externalDocumentReferenceErrorsChannel = Channel.CreateUnbounded<FileValidationResult>();
            await externalDocumentReferenceChannel.Writer.WriteAsync(new ExternalDocumentReferenceInfo
            {
                DocumentNamespace = "namespace",
                ExternalDocumentName = "name",
                Checksum = new List<Checksum> { new Checksum { Algorithm = AlgorithmName.SHA1,
                                                               ChecksumValue = "abc"
                                                             } }
            });
            externalDocumentReferenceChannel.Writer.Complete();
            externalDocumentReferenceErrorsChannel.Writer.Complete();
            sBOMReaderForExternalDocumentReferenceMock
            .Setup(p => p.ParseSBOMFile(It.IsAny<ChannelReader<string>>()))
            .Returns((externalDocumentReferenceChannel, externalDocumentReferenceErrorsChannel));

            var directoryTraversingProvider = new DirectoryTraversingFileToJsonProvider
            {
                ChannelUtils = new ChannelUtils(),
                DirectoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                FileHasher = new FileHasher(
                    hashCodeGeneratorMock.Object,
                    new DropValidatorManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                    mockLogger.Object,
                    configurationMock.Object,
                    sbomConfigs,
                    manifestGeneratorProvider,
                    new FileTypeUtils()),
                FileFilterer = new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object),
                FileHashWriter = new FileInfoWriter(
                    manifestGeneratorProvider,
                    mockLogger.Object,
                    fileSystemUtilsExtensionMock.Object,
                    configurationMock.Object),
                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                InternalSBOMFileInfoDeduplicator = new InternalSBOMFileInfoDeduplicator()
            };

            var fileListBasedProvider = new FileListBasedFileToJsonProvider
            {
                ChannelUtils = new ChannelUtils(),
                FileHasher = new FileHasher(
                    hashCodeGeneratorMock.Object,
                    new DropValidatorManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                    mockLogger.Object,
                    configurationMock.Object,
                    sbomConfigs,
                    manifestGeneratorProvider,
                    new FileTypeUtils()),
                FileFilterer = new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object),
                FileHashWriter = new FileInfoWriter(
                    manifestGeneratorProvider,
                    mockLogger.Object,
                    fileSystemUtilsExtensionMock.Object,
                    configurationMock.Object),

                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                ListWalker = new FileListEnumerator(fileSystemMock.Object, mockLogger.Object)
            };

            var cgPackagesProvider = new CGScannedPackagesProvider
            {
                ChannelUtils = new ChannelUtils(),
                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                PackageInfoConverter = packageInfoConverterMock.Object,
                PackageInfoJsonWriter = new PackageInfoJsonWriter(
                    manifestGeneratorProvider,
                    mockLogger.Object),
                PackagesWalker = new PackagesWalker(mockLogger.Object, mockDetector.Object, configurationMock.Object, sbomConfigs),
                SBOMConfigs = sbomConfigs
            };

            var externalDocumentReferenceProvider = new ExternalDocumentReferenceProvider
            {
                ChannelUtils = new ChannelUtils(),
                ExternalDocumentReferenceWriter = new ExternalDocumentReferenceWriter(
                    manifestGeneratorProvider,
                    mockLogger.Object),
                SPDXSBOMReaderForExternalDocumentReference = sBOMReaderForExternalDocumentReferenceMock.Object,
                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                ListWalker = new FileListEnumerator(fileSystemMock.Object, mockLogger.Object)
            };

            var sourcesProvider = new List<ISourcesProvider>
            {
                { fileListBasedProvider },
                { directoryTraversingProvider },
                { cgPackagesProvider },
                { externalDocumentReferenceProvider }
            };

            var fileArrayGenerator = new FileArrayGenerator
            {
                SourcesProviders = sourcesProvider,
                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                SBOMConfigs = sbomConfigs,
                Recorder = recorderMock.Object
            };

            var packageArrayGenerator = new PackageArrayGenerator
            {
                ChannelUtils = new ChannelUtils(),
                Configuration = configurationMock.Object,
                Log = mockLogger.Object,
                SBOMConfigs = sbomConfigs,
                SourcesProviders = sourcesProvider,
                Recorder = recorderMock.Object
            };

            var externalDocumentReferenceGenerator = new ExternalDocumentReferenceGenerator
            {
                SourcesProviders = sourcesProvider,
                Log = mockLogger.Object,
                Configuration = configurationMock.Object,
                SBOMConfigs = sbomConfigs,
                Recorder = recorderMock.Object
            };

            relationshipArrayGenerator
                .Setup(r => r.GenerateAsync())
                .ReturnsAsync(await Task.FromResult(new List<FileValidationResult>()));

            var workflow = new SBOMGenerationWorkflow
            {
                Configuration = configurationMock.Object,
                FileSystemUtils = fileSystemMock.Object,
                Log = mockLogger.Object,
                FileArrayGenerator = fileArrayGenerator,
                PackageArrayGenerator = packageArrayGenerator,
                RelationshipsArrayGenerator = relationshipArrayGenerator.Object,
                ExternalDocumentReferenceGenerator = externalDocumentReferenceGenerator,
                SBOMConfigs = sbomConfigs,
                OSUtils = mockOSUtils.Object,
                Recorder = recorderMock.Object,
            };

            Assert.IsTrue(await workflow.RunAsync());

            var result = Encoding.UTF8.GetString(manifestStream.ToArray());
            var resultJson = JObject.Parse(result);

            Assert.AreEqual(resultJson["Version"], "1.0.0");
            Assert.AreEqual(resultJson["Build"], 12);
            Assert.AreEqual(resultJson["Definition"], "test");

            var outputs = resultJson["Outputs"];
            JArray sortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));
            var expectedJson = JObject.Parse(GoodJson);
            JArray expectedSortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));

            var packages = resultJson["Packages"];
            Assert.IsTrue(packages.Count() == 4);

            Assert.IsTrue(JToken.DeepEquals(sortedOutputs, expectedSortedOutputs));

            configurationMock.VerifyAll();
            fileSystemMock.VerifyAll();
            hashCodeGeneratorMock.VerifyAll();
            mockLogger.VerifyAll();
            fileSystemMock.Verify(x => x.FileExists(jsonFilePath), Times.Once);
            fileSystemMock.Verify(x => x.OpenWrite($"{jsonFilePath}.sha256"), Times.Once);
        }

        [TestMethod]
        public async Task ManifestGenerationWorkflowTests_SBOMDirExists_Throws()
        {
            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            var sbomConfig = new SbomConfig(fileSystemMock.Object)
            {
                ManifestInfo = Constants.TestManifestInfo,
                ManifestJsonDirPath = "/root/_manifest",
                ManifestJsonFilePath = "/root/_manifest/manifest.json"
            };
            var workflow = new SBOMGenerationWorkflow
            {
                Configuration = configurationMock.Object,
                FileSystemUtils = fileSystemMock.Object,
                Log = mockLogger.Object,
                SBOMConfigs = new Mock<ISbomConfigProvider>().Object,
                Recorder = recorderMock.Object
            };

            Assert.IsFalse(await workflow.RunAsync());
        }

        [TestMethod]
        public async Task ManifestGenerationWorkflowTests_SBOMDir_NotDefault_NotDeleted()
        {
            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            var sbomConfig = new SbomConfig(fileSystemMock.Object)
            {
                ManifestInfo = Constants.TestManifestInfo,
                ManifestJsonDirPath = "/root/_manifest",
                ManifestJsonFilePath = "/root/_manifest/manifest.json"
            };
            configurationMock.SetupGet(x => x.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest"), Source = SettingSource.CommandLine });
            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            fileSystemMock.Setup(f => f.DeleteDir(It.IsAny<string>(), true)).Verifiable();
            var fileArrayGeneratorMock = new Mock<IJsonArrayGenerator>();
            fileArrayGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(new List<FileValidationResult> { new FileValidationResult() });

            var workflow = new SBOMGenerationWorkflow
            {
                Configuration = configurationMock.Object,
                FileSystemUtils = fileSystemMock.Object,
                Log = mockLogger.Object,
                SBOMConfigs = new Mock<ISbomConfigProvider>().Object,
                Recorder = recorderMock.Object,
                FileArrayGenerator = fileArrayGeneratorMock.Object
            };

            var result = await workflow.RunAsync();

            fileSystemMock.Verify(f => f.DeleteDir(It.IsAny<string>(), true), Times.Never);
            Assert.IsFalse(result);
        }

        private const string GoodJson = "{\"Outputs\":[{\"Source\":\"/child1/file2\",\"AzureArtifactsHash\":" +
            "\"/root/child1/file2hash\",\"Sha256Hash\":\"/root/child1/file2hash\"},{\"Source\":\"/child1/file1\"," +
            "\"AzureArtifactsHash\":\"/root/child1/file1hash\",\"Sha256Hash\":\"/root/child1/file1hash\"},{\"Source\":" +
            "\"/child2/file3\",\"AzureArtifactsHash\":\"/root/child2/file3hash\",\"Sha256Hash\":\"/root/child2/file3hash\"}" +
            ",{\"Source\":\"/child2/file4\",\"AzureArtifactsHash\":\"/root/child2/file4hash\",\"Sha256Hash\":\"/root/child2" +
            "/file4hash\"},{\"Source\":\"/child2/grandchild1/file6\",\"AzureArtifactsHash\":\"/root/child2/grandchild1/" +
            "file6hash\",\"Sha256Hash\":\"/root/child2/grandchild1/file6hash\"},{\"Source\":\"/child2/grandchild1/file10" +
            "\",\"AzureArtifactsHash\":\"/root/child2/grandchild1/file10hash\",\"Sha256Hash\":\"/root/child2/grandchild1" +
            "/file10hash\"},{\"Source\":\"/child2/grandchild1/file9\",\"AzureArtifactsHash\":\"/root/child2/grandchild1" +
            "/file9hash\",\"Sha256Hash\":\"/root/child2/grandchild1/file9hash\"},{\"Source\":\"/child3/file11\",\"Azure" +
            "ArtifactsHash\":\"/root/child3/file11hash\",\"Sha256Hash\":\"/root/child3/file11hash\"},{\"Source\":\"/chi" +
            "ld2/file5\",\"AzureArtifactsHash\":\"/root/child2/file5hash\",\"Sha256Hash\":\"/root/child2/file5hash\"},{" +
            "\"Source\":\"/child2/grandchild1/file7\",\"AzureArtifactsHash\":\"/root/child2/grandchild1/file7hash\",\"S" +
            "ha256Hash\":\"/root/child2/grandchild1/file7hash\"},{\"Source\":\"/child3/file12\",\"AzureArtifactsHash\":" +
            "\"/root/child3/file12hash\",\"Sha256Hash\":\"/root/child3/file12hash\"}]}";
    }
}
