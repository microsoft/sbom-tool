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
using Microsoft.ComponentDetection.Orchestrator.Commands;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.PackageDetails;
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
using Checksum = Microsoft.Sbom.Contracts.Checksum;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using IComponentDetector = Microsoft.Sbom.Api.Utils.IComponentDetector;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class ManifestGenerationWorkflowTests
{
    private readonly Mock<IRecorder> recorderMock = new Mock<IRecorder>();

    private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>();
    private readonly Mock<IConfiguration> configurationMock = new Mock<IConfiguration>();
    private readonly Mock<ILogger<SbomConfigProvider>> mockSbomConfigProividerLogger = new Mock<ILogger<SbomConfigProvider>>();
    private readonly Mock<ILogger<MetadataBuilder>> mockMetadataBuilderLogger = new Mock<ILogger<MetadataBuilder>>();
    private readonly Mock<ILogger<DirectoryTraversingFileToJsonProvider>> mockDirectoryTraversingFileToJsonProviderLogger = new Mock<ILogger<DirectoryTraversingFileToJsonProvider>>();
    private readonly Mock<ILogger<FileHasher>> mockFileHasherLogger = new Mock<ILogger<FileHasher>>();
    private readonly Mock<ILogger<SbomGenerationWorkflow>> mockSbomGenerationWorkflowLogger = new Mock<ILogger<SbomGenerationWorkflow>>();
    private readonly Mock<ILogger<ManifestFolderFilterer>> mockManifestFolderFiltererLogger = new Mock<ILogger<ManifestFolderFilterer>>();
    private readonly Mock<ILogger<FileInfoWriter>> mockFileInfoWriterLogger = new Mock<ILogger<FileInfoWriter>>();
    private readonly Mock<ILogger<PackagesWalker>> mockPackagesWalkerLogger = new Mock<ILogger<PackagesWalker>>();
    private readonly Mock<ILogger<PackageArrayGenerator>> mockPackageArrayGeneratorLogger = new Mock<ILogger<PackageArrayGenerator>>();
    private readonly Mock<ILogger<FileListBasedFileToJsonProvider>> mockFileListBasedFileToJsonProviderLogger = new Mock<ILogger<FileListBasedFileToJsonProvider>>();
    private readonly Mock<ILogger<FileArrayGenerator>> mockFileArrayGeneratorLogger = new Mock<ILogger<FileArrayGenerator>>();
    private readonly Mock<ILogger<DirectoryWalker>> mockDirectoryWalkerLogger = new Mock<ILogger<DirectoryWalker>>();
    private readonly Mock<ILogger<PackageInfoJsonWriter>> mockPackageInfoJsonWriterLogger = new Mock<ILogger<PackageInfoJsonWriter>>();
    private readonly Mock<ILogger<FileListEnumerator>> mockFileListEnumeratorLogger = new Mock<ILogger<FileListEnumerator>>();
    private readonly Mock<ILogger<ExternalDocumentReferenceProvider>> mockExternalDocumentReferenceProviderLogger = new Mock<ILogger<ExternalDocumentReferenceProvider>>();
    private readonly Mock<ILogger<ExternalDocumentReferenceWriter>> mockExternalDocumentReferenceWriterLogger = new Mock<ILogger<ExternalDocumentReferenceWriter>>();
    private readonly Mock<ILogger<CGScannedPackagesProvider>> mockCGScannedPackagesProviderLogger = new Mock<ILogger<CGScannedPackagesProvider>>();
    private readonly Mock<ILogger<ExternalDocumentReferenceGenerator>> mockExternalDocumentReferenceGeneratorLogger = new Mock<ILogger<ExternalDocumentReferenceGenerator>>();
    private static readonly Mock<ILogger<ComponentDetectorCachedExecutor>> MockComponentDetectorCachedExecutorLogger = new Mock<ILogger<ComponentDetectorCachedExecutor>>();
    private readonly Mock<IHashCodeGenerator> hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
    private readonly Mock<IOSUtils> mockOSUtils = new Mock<IOSUtils>();
    private readonly Mock<IManifestConfigHandler> mockConfigHandler = new Mock<IManifestConfigHandler>();
    private readonly Mock<IMetadataProvider> mockMetadataProvider = new Mock<IMetadataProvider>();
    private readonly Mock<ComponentDetectorCachedExecutor> mockDetector = new Mock<ComponentDetectorCachedExecutor>(MockComponentDetectorCachedExecutorLogger.Object, new Mock<IComponentDetector>().Object);
    private readonly Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>> relationshipArrayGenerator = new Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>>();
    private readonly Mock<ComponentToPackageInfoConverter> packageInfoConverterMock = new Mock<ComponentToPackageInfoConverter>();
    private readonly Mock<ISBOMReaderForExternalDocumentReference> sBOMReaderForExternalDocumentReferenceMock = new Mock<ISBOMReaderForExternalDocumentReference>();
    private readonly Mock<IFileSystemUtilsExtension> fileSystemUtilsExtensionMock = new Mock<IFileSystemUtilsExtension>();
    private readonly Mock<ILicenseInformationFetcher> licenseInformationFetcherMock = new Mock<ILicenseInformationFetcher>();
    private readonly Mock<IPackageDetailsFactory> mockPackageDetailsFactory = new Mock<IPackageDetailsFactory>();

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
            mockMetadataBuilderLogger.Object,
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
            mockSbomConfigProividerLogger.Object,
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
        fileSystemMock.Setup(f => f.WriteAllText(It.Is<string>(c => c == "/root/_manifest/manifest.json.sha256"), It.IsAny<string>()));

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()))
            .Returns((string fileName, AlgorithmName[] algos) =>
                algos.Select(a =>
                        new Checksum
                        {
                            ChecksumValue = $"{fileName}hash",
                            Algorithm = a
                        })
                    .ToArray());

        var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, mockOSUtils.Object);
        manifestFilterMock.Init();

        var scannedComponents = new List<ScannedComponent>();
        for (var i = 1; i < 4; i++)
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

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<ScanSettings>())).Returns(Task.FromResult(scanResult));

        var packagesChannel = Channel.CreateUnbounded<SbomPackage>();
        var errorsChannel = Channel.CreateUnbounded<FileValidationResult>();
        foreach (var component in scannedComponents)
        {
            await packagesChannel.Writer.WriteAsync(new SbomPackage { PackageName = component.GetHashCode().ToString() });
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

        var directoryTraversingProvider = new DirectoryTraversingFileToJsonProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockDirectoryTraversingFileToJsonProviderLogger.Object,
            new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                mockFileHasherLogger.Object,
                configurationMock.Object,
                sbomConfigs,
                manifestGeneratorProvider,
                new FileTypeUtils()),
            new ManifestFolderFilterer(manifestFilterMock, mockManifestFolderFiltererLogger.Object),
            new FileInfoWriter(
                manifestGeneratorProvider,
                mockFileInfoWriterLogger.Object),
            new InternalSBOMFileInfoDeduplicator(),
            new DirectoryWalker(fileSystemMock.Object, mockDirectoryWalkerLogger.Object, configurationMock.Object));

        var fileListBasedProvider = new FileListBasedFileToJsonProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockFileListBasedFileToJsonProviderLogger.Object,
            new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                mockFileHasherLogger.Object,
                configurationMock.Object,
                sbomConfigs,
                manifestGeneratorProvider,
                new FileTypeUtils()),
            new ManifestFolderFilterer(manifestFilterMock, mockManifestFolderFiltererLogger.Object),
            new FileInfoWriter(
                manifestGeneratorProvider,
                mockFileInfoWriterLogger.Object),
            new InternalSBOMFileInfoDeduplicator(),
            new FileListEnumerator(fileSystemMock.Object, mockFileListEnumeratorLogger.Object));

        var cgPackagesProvider = new CGScannedPackagesProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockCGScannedPackagesProviderLogger.Object,
            sbomConfigs,
            new PackageInfoJsonWriter(
                manifestGeneratorProvider,
                mockPackageInfoJsonWriterLogger.Object),
            packageInfoConverterMock.Object,
            new PackagesWalker(mockPackagesWalkerLogger.Object, mockDetector.Object, configurationMock.Object, sbomConfigs, fileSystemMock.Object, mockPackageDetailsFactory.Object, licenseInformationFetcherMock.Object),
            mockPackageDetailsFactory.Object,
            licenseInformationFetcherMock.Object);

        var externalDocumentReferenceProvider = new ExternalDocumentReferenceProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockExternalDocumentReferenceProviderLogger.Object,
            new FileListEnumerator(fileSystemMock.Object, mockFileListEnumeratorLogger.Object),
            sBOMReaderForExternalDocumentReferenceMock.Object,
            new ExternalDocumentReferenceWriter(
                manifestGeneratorProvider,
                mockExternalDocumentReferenceWriterLogger.Object),
            new ExternalReferenceDeduplicator());

        var sourcesProvider = new List<ISourcesProvider>
        {
            { fileListBasedProvider },
            { directoryTraversingProvider },
            { cgPackagesProvider },
            { externalDocumentReferenceProvider }
        };

        var fileArrayGenerator = new FileArrayGenerator(sbomConfigs, sourcesProvider, recorderMock.Object, mockFileArrayGeneratorLogger.Object);

        var packageArrayGenerator = new PackageArrayGenerator(mockPackageArrayGeneratorLogger.Object, sbomConfigs, sourcesProvider, recorderMock.Object);

        var externalDocumentReferenceGenerator = new ExternalDocumentReferenceGenerator(mockExternalDocumentReferenceGeneratorLogger.Object, sbomConfigs, sourcesProvider, recorderMock.Object);

        relationshipArrayGenerator
            .Setup(r => r.GenerateAsync())
            .ReturnsAsync(await Task.FromResult(new List<FileValidationResult>()));

        var workflow = new SbomGenerationWorkflow(
            configurationMock.Object,
            fileSystemMock.Object,
            mockSbomGenerationWorkflowLogger.Object,
            fileArrayGenerator,
            packageArrayGenerator,
            relationshipArrayGenerator.Object,
            externalDocumentReferenceGenerator,
            sbomConfigs,
            mockOSUtils.Object,
            recorderMock.Object);

        Assert.IsTrue(await workflow.RunAsync());

        var result = Encoding.UTF8.GetString(manifestStream.ToArray());
        var resultJson = JObject.Parse(result);

        Assert.AreEqual(resultJson["Version"], "1.0.0");
        Assert.AreEqual(resultJson["Build"], 12);
        Assert.AreEqual(resultJson["Definition"], "test");

        var outputs = resultJson["Outputs"];
        var sortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));
        var expectedSortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));

        var packages = resultJson["Packages"];
        Assert.IsTrue(packages.Count() == 4);

        Assert.IsTrue(JToken.DeepEquals(sortedOutputs, expectedSortedOutputs));

        configurationMock.VerifyAll();
        fileSystemMock.VerifyAll();
        hashCodeGeneratorMock.VerifyAll();
        mockSbomGenerationWorkflowLogger.VerifyAll();
        fileSystemMock.Verify(x => x.FileExists(jsonFilePath), Times.Once);
        fileSystemMock.Verify(x => x.WriteAllText($"{jsonFilePath}.sha256", It.IsAny<string>()), Times.Once);
    }

    [TestMethod]
    public async Task ManifestGenerationWorkflowTests_SBOMDirExists_Throws()
    {
        configurationMock.SetupGet(x => x.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest"), Source = SettingSource.Default });
        fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        mockOSUtils.Setup(o => o.GetEnvironmentVariable(It.IsAny<string>())).Returns("false");
        var sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = Constants.TestManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/manifest.json"
        };
        var workflow = new SbomGenerationWorkflow(
            configurationMock.Object,
            fileSystemMock.Object,
            mockSbomGenerationWorkflowLogger.Object,
            new Mock<IJsonArrayGenerator<FileArrayGenerator>>().Object,
            new Mock<IJsonArrayGenerator<PackageArrayGenerator>>().Object,
            new Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>>().Object,
            new Mock<IJsonArrayGenerator<ExternalDocumentReferenceGenerator>>().Object,
            new Mock<ISbomConfigProvider>().Object,
            mockOSUtils.Object,
            recorderMock.Object);

        Assert.IsFalse(await workflow.RunAsync());
        recorderMock.Verify(r => r.RecordException(It.IsAny<ManifestFolderExistsException>()), Times.Once);
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
        var fileArrayGeneratorMock = new Mock<IJsonArrayGenerator<FileArrayGenerator>>();
        fileArrayGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(new List<FileValidationResult> { new FileValidationResult() });

        var workflow = new SbomGenerationWorkflow(
            configurationMock.Object,
            fileSystemMock.Object,
            mockSbomGenerationWorkflowLogger.Object,
            fileArrayGeneratorMock.Object,
            new Mock<IJsonArrayGenerator<PackageArrayGenerator>>().Object,
            new Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>>().Object,
            new Mock<IJsonArrayGenerator<ExternalDocumentReferenceGenerator>>().Object,
            new Mock<ISbomConfigProvider>().Object,
            mockOSUtils.Object,
            recorderMock.Object);

        var result = await workflow.RunAsync();

        fileSystemMock.Verify(f => f.DeleteDir(It.IsAny<string>(), true), Times.Once);
        Assert.IsFalse(result);
    }
}
