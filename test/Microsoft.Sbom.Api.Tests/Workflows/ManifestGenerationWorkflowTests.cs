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
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Metadata;
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
using GenerationResult = Microsoft.Sbom.Api.Workflows.Helpers.GenerationResult;
using Generator30 = Microsoft.Sbom.Parsers.Spdx30SbomParser.Generator;
using IComponentDetector = Microsoft.Sbom.Api.Utils.IComponentDetector;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Workflows.Tests;

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
    private readonly Mock<ComponentDetectorCachedExecutor> mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);
    private readonly Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>> relationshipArrayGenerator = new Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>>();
    private readonly Mock<ComponentToPackageInfoConverter> packageInfoConverterMock = new Mock<ComponentToPackageInfoConverter>();
    private readonly Mock<ISbomReaderForExternalDocumentReference> sBOMReaderForExternalDocumentReferenceMock = new Mock<ISbomReaderForExternalDocumentReference>();
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
    [DataRow("test", true, true)]
    [DataRow("test", false, false)]
    [DataRow("test", true, false)]
    [DataRow("test", false, true)]
    [DataRow("3.0", true, true)]
    [DataRow("3.0", false, false)]
    [DataRow("3.0", true, false)]
    [DataRow("3.0", false, true)]
    public async Task ManifestGenerationWorkflowTests_Succeeds(string spdxVersionForGenerator, bool deleteExistingManifestDir, bool isDefaultSourceManifestDirPath)
    {
        var manifestInfoPerSpdxVersion = new Dictionary<string, ManifestInfo>
        {
            { "test", Constants.TestManifestInfo },
            { "3.0", Constants.SPDX30ManifestInfo }
        };

        ManifestGeneratorProvider manifestGeneratorProvider = null;
        if (spdxVersionForGenerator == "test")
        {
            manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        }
        else if (spdxVersionForGenerator == "3.0")
        {
            manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new Generator30() });
        }

        manifestGeneratorProvider.Init();

        var metadataBuilder = new MetadataBuilder(
            mockLogger.Object,
            manifestGeneratorProvider,
            manifestInfoPerSpdxVersion[spdxVersionForGenerator],
            recorderMock.Object);
        var jsonFilePath = "/root/_manifest/manifest.json";

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = manifestInfoPerSpdxVersion[spdxVersionForGenerator],
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
            { MetadataKey.SbomToolName, "testMicrosoft" },
            { MetadataKey.SbomToolVersion, "Tool.Version" },
            { MetadataKey.PackageVersion, "Package.Version" },
            { MetadataKey.PackageSupplier, "testPackageSupplier" }
        });

        var localMetadataProvider = new LocalMetadataProvider(configurationMock.Object);
        var sbomConfigs = new SbomConfigProvider(
            manifestConfigHandlers: new IManifestConfigHandler[] { mockConfigHandler.Object },
            metadataProviders: new IMetadataProvider[] { localMetadataProvider, mockMetadataProvider.Object },
            logger: mockLogger.Object,
            recorder: recorderMock.Object);

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

        // Added config settings necessary for 3.0 SBOM generation
        if (spdxVersionForGenerator == "3.0")
        {
            configurationMock.SetupGet(c => c.PackageName).Returns(new ConfigurationSetting<string>("the-package-name"));
            configurationMock.SetupGet(c => c.PackageVersion).Returns(new ConfigurationSetting<string>("the-package-version"));
            configurationMock.SetupGet(c => c.NamespaceUriUniquePart).Returns(new ConfigurationSetting<string>("some-custom-value-here"));
            configurationMock.SetupGet(c => c.NamespaceUriBase).Returns(new ConfigurationSetting<string>("http://sbom.microsoft"));
        }

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
            .Setup(p => p.ParseSbomFile(It.IsAny<ChannelReader<string>>()))
            .Returns((externalDocumentReferenceChannel, externalDocumentReferenceErrorsChannel));

        var directoryTraversingProvider = new DirectoryTraversingFileToJsonProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockLogger.Object,
            new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                mockLogger.Object,
                configurationMock.Object,
                sbomConfigs,
                manifestGeneratorProvider,
                new FileTypeUtils()),
            new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object),
            new FileInfoWriter(
                manifestGeneratorProvider,
                mockLogger.Object),
            new InternalSbomFileInfoDeduplicator(),
            new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object));

        var fileListBasedProvider = new FileListBasedFileToJsonProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockLogger.Object,
            new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
                mockLogger.Object,
                configurationMock.Object,
                sbomConfigs,
                manifestGeneratorProvider,
                new FileTypeUtils()),
            new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object),
            new FileInfoWriter(
                manifestGeneratorProvider,
                mockLogger.Object),
            new InternalSbomFileInfoDeduplicator(),
            new FileListEnumerator(fileSystemMock.Object, mockLogger.Object));

        var cgPackagesProvider = new CGScannedPackagesProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockLogger.Object,
            sbomConfigs,
            new PackageInfoJsonWriter(
                manifestGeneratorProvider,
                mockLogger.Object),
            packageInfoConverterMock.Object,
            new PackagesWalker(mockLogger.Object, mockDetector.Object, configurationMock.Object, sbomConfigs, fileSystemMock.Object, mockPackageDetailsFactory.Object, licenseInformationFetcherMock.Object),
            mockPackageDetailsFactory.Object,
            licenseInformationFetcherMock.Object);

        var externalDocumentReferenceProvider = new ExternalDocumentReferenceProvider(
            configurationMock.Object,
            new ChannelUtils(),
            mockLogger.Object,
            new FileListEnumerator(fileSystemMock.Object, mockLogger.Object),
            sBOMReaderForExternalDocumentReferenceMock.Object,
            new ExternalDocumentReferenceWriter(
                manifestGeneratorProvider,
                mockLogger.Object),
            new ExternalReferenceDeduplicator());

        var sourcesProvider = new List<ISourcesProvider>
        {
            { fileListBasedProvider },
            { directoryTraversingProvider },
            { cgPackagesProvider },
            { externalDocumentReferenceProvider }
        };

        var fileArrayGenerator = new FileArrayGenerator(sourcesProvider, recorderMock.Object, mockLogger.Object);

        var packageArrayGenerator = new PackageArrayGenerator(mockLogger.Object, sourcesProvider, recorderMock.Object, sbomConfigs);

        var externalDocumentReferenceGenerator = new ExternalDocumentReferenceGenerator(mockLogger.Object, sourcesProvider, recorderMock.Object);

        var generationResult = new GenerationResult(new List<FileValidationResult>(), new Dictionary<IManifestToolJsonSerializer, List<System.Text.Json.JsonDocument>>());
        relationshipArrayGenerator
            .Setup(r => r.GenerateAsync())
            .ReturnsAsync(generationResult);

        var workflow = new SbomGenerationWorkflow(
            configurationMock.Object,
            fileSystemMock.Object,
            mockLogger.Object,
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

        if (spdxVersionForGenerator == "test")
        {
            Assert.AreEqual("1.0.0", resultJson["Version"]);
            Assert.AreEqual(12, resultJson["Build"]);
            Assert.AreEqual("test", resultJson["Definition"]);

            var outputs = resultJson["Outputs"];
            var sortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));
            var expectedSortedOutputs = new JArray(outputs.OrderBy(obj => (string)obj["Source"]));

            var packages = resultJson["Packages"];
            Assert.AreEqual(4, packages.Count());

            Assert.IsTrue(JToken.DeepEquals(sortedOutputs, expectedSortedOutputs));
        }
        else
        {
            // Test context is correct
            var context = resultJson["@context"].ToArray();
            Assert.AreEqual("https://spdx.org/rdf/3.0.1/spdx-context.json", context.FirstOrDefault().ToString());

            // Test elements were generated correctly
            var elements = resultJson["@graph"].ToArray();
            var packages = elements.Where(element => element["type"].ToString() == "software_Package").ToList();
            Assert.AreEqual(4, packages.Count);

            var creationInfo = elements.Where(element => element["type"].ToString() == "CreationInfo").ToList();
            Assert.AreEqual(1, creationInfo.Count);

            // Test deduplication
            var noAssertionElements = elements.Where(element => element["spdxId"].ToString() == "SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B").ToList();
            Assert.AreEqual(1, noAssertionElements.Count);

            var organizationElements = elements.Where(element => element["type"].ToString() == "Organization").ToList();
            Assert.AreEqual(3, organizationElements.Count);

            var organizationElement = elements.Where(element => element["spdxId"].ToString() == "SPDXRef-Organization-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969").ToList();
            Assert.AreEqual(1, organizationElement.Count);
        }

        configurationMock.VerifyAll();
        fileSystemMock.VerifyAll();
        hashCodeGeneratorMock.VerifyAll();
        mockLogger.VerifyAll();
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
            mockLogger.Object,
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

        var generationResult = new GenerationResult(new List<FileValidationResult>(), new Dictionary<IManifestToolJsonSerializer, List<System.Text.Json.JsonDocument>>());
        var generationResultWithFailure = new GenerationResult(new List<FileValidationResult> { new FileValidationResult() }, new Dictionary<IManifestToolJsonSerializer, List<System.Text.Json.JsonDocument>>());

        var fileArrayGeneratorMock = new Mock<IJsonArrayGenerator<FileArrayGenerator>>();
        fileArrayGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(generationResultWithFailure);

        var packageArrayGeneratorMock = new Mock<IJsonArrayGenerator<PackageArrayGenerator>>();
        packageArrayGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(generationResult);

        var relationshipsArrayGeneratorMock = new Mock<IJsonArrayGenerator<RelationshipsArrayGenerator>>();
        relationshipsArrayGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(generationResult);

        var externalDocumentReferenceGeneratorMock = new Mock<IJsonArrayGenerator<ExternalDocumentReferenceGenerator>>();
        externalDocumentReferenceGeneratorMock.Setup(f => f.GenerateAsync()).ReturnsAsync(generationResultWithFailure);

        var sbomConfigsMock = new Mock<ISbomConfigProvider>();
        sbomConfigsMock.Setup(f => f.GetManifestInfos()).Returns(new List<ManifestInfo> { Constants.TestManifestInfo });

        var workflow = new SbomGenerationWorkflow(
            configurationMock.Object,
            fileSystemMock.Object,
            mockLogger.Object,
            fileArrayGeneratorMock.Object,
            packageArrayGeneratorMock.Object,
            relationshipsArrayGeneratorMock.Object,
            externalDocumentReferenceGeneratorMock.Object,
            sbomConfigsMock.Object,
            mockOSUtils.Object,
            recorderMock.Object);

        var result = await workflow.RunAsync();

        fileArrayGeneratorMock.VerifyAll();
        packageArrayGeneratorMock.VerifyAll();
        relationshipsArrayGeneratorMock.VerifyAll();
        externalDocumentReferenceGeneratorMock.VerifyAll();
        fileSystemMock.Verify(f => f.DeleteDir(It.IsAny<string>(), true), Times.Once);
        Assert.IsFalse(result);
    }
}
