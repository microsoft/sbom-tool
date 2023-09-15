// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JsonAsynchronousNodeKit;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parser;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;
using SpdxChecksum = Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Checksum;

namespace Microsoft.Sbom.Workflows;

#nullable enable

[TestClass]
public class SbomParserBasedValidationWorkflowTests : ValidationWorkflowTestsBase
{
    private readonly Mock<ILogger> mockLogger = new();
    private readonly Mock<IOSUtils> mockOSUtils = new();
    private readonly Mock<IFileSystemUtilsExtension> fileSystemUtilsExtensionMock = new();
    private readonly Mock<ISignValidator> signValidatorMock = new();
    private readonly Mock<ISignValidationProvider> signValidationProviderMock = new();

    [TestInitialize]
    public void Init()
    {
        signValidatorMock.Setup(s => s.Validate()).Returns(true);
        signValidationProviderMock.Setup(s => s.Get()).Returns(signValidatorMock.Object);
    }

    [TestCleanup]
    public void Reset()
    {
        FileHashesDictionarySingleton.Reset();
    }

    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsSuccessAndValidationFailures_IgnoreMissingTrue_Succeeds()
    {
        var manifestParserProvider = new Mock<IManifestParserProvider>();
        var manifestInterface = new Mock<IManifestInterface>();
        var sbomParser = new Mock<ISbomParser>();
        var configurationMock = new Mock<IConfiguration>();
        var sbomConfigs = new Mock<ISbomConfigProvider>();
        var fileSystemMock = GetDefaultFileSystemMock();
        var outputWriterMock = new Mock<IOutputWriter>();
        var recorder = new Mock<IRecorder>();
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();

        var dictionary = GetSpdxFilesDictionary();
        dictionary["/child2/grandchild1/file9"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/grandchild1/file9hash" } };
        dictionary["/child2/grandchild1/file7"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/grandchild1/file7hash" } };
        dictionary["/child2/grandchild1/file10"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/grandchild1/file10hash" } };

        sbomParser.SetupSequence(p => p.Next())
            .Returns(new FilesResult(new ParserStateResult(SPDXParser.FilesProperty, GetSpdxFiles(dictionary), ExplicitField: true, YieldReturn: true)))
            .Returns((ParserStateResult?)null);

        manifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>()))
            .Returns(sbomParser.Object);
        manifestParserProvider.Setup(m => m.Get(It.IsAny<ManifestInfo>())).Returns(manifestInterface.Object);

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
        configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
        configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { Constants.SPDX22ManifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = Constants.SPDX22ManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/spdx_2.2/manifest.spdx.json",
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(Constants.SPDX22ManifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead("/root/_manifest/spdx_2.2/manifest.spdx.json")).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

        fileSystemUtilsExtensionMock.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns((string fileName, AlgorithmName[] algos) =>
                new Checksum[]
                {
                    new Checksum
                    {
                        ChecksumValue = $"{fileName}hash",
                        Algorithm = Constants.DefaultHashAlgorithmName
                    }
                });

        var fileHasher = new FileHasher(
            hashCodeGeneratorMock.Object,
            new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
            mockLogger.Object,
            configurationMock.Object,
            new Mock<ISbomConfigProvider>().Object,
            new ManifestGeneratorProvider(null),
            new FileTypeUtils());

        var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, mockOSUtils.Object);
        manifestFilterMock.Init();
        var fileFilterer = new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object);

        var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
        rootFileFilterMock.Init();

        var hashValidator = new ConcurrentSha256HashValidator(FileHashesDictionarySingleton.Instance);
        var enumeratorChannel = new EnumeratorChannel(mockLogger.Object);
        var fileConverter = new SbomFileToFileInfoConverter(new FileTypeUtils());
        var spdxFileFilterer = new FileFilterer(rootFileFilterMock, mockLogger.Object, configurationMock.Object, fileSystemMock.Object);

        var filesValidator = new FilesValidator(
            directoryWalker,
            configurationMock.Object,
            mockLogger.Object,
            fileHasher,
            fileFilterer,
            hashValidator,
            enumeratorChannel,
            fileConverter,
            FileHashesDictionarySingleton.Instance,
            spdxFileFilterer);

        var validator = new SbomParserBasedValidationWorkflow(
            recorder.Object,
            signValidationProviderMock.Object,
            mockLogger.Object,
            manifestParserProvider.Object,
            configurationMock.Object,
            sbomConfigs.Object,
            filesValidator,
            validationResultGenerator,
            outputWriterMock.Object,
            fileSystemMock.Object);

        var result = await validator.RunAsync();
        Assert.IsTrue(result);
        var nodeValidationResults = validationResultGenerator.NodeValidationResults;

        var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
        Assert.AreEqual(0, additionalFileErrors.Count);

        var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
        Assert.AreEqual(1, missingFileErrors.Count);
        Assert.AreEqual("./child2/grandchild2/file10", missingFileErrors.First().Path);

        var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
        Assert.AreEqual(0, invalidHashErrors.Count);

        var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
        Assert.AreEqual(0, otherErrors.Count);

        configurationMock.VerifyAll();
        signValidatorMock.VerifyAll();
        fileSystemMock.VerifyAll();
    }

    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsSuccessAndValidationFailures_Succeeds()
    {
        var manifestParserProvider = new Mock<IManifestParserProvider>();
        var manifestInterface = new Mock<IManifestInterface>();
        var sbomParser = new Mock<ISbomParser>();
        var configurationMock = new Mock<IConfiguration>();
        var sbomConfigs = new Mock<ISbomConfigProvider>();
        var fileSystemMock = GetDefaultFileSystemMock();
        var outputWriterMock = new Mock<IOutputWriter>();
        var recorder = new Mock<IRecorder>();
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();

        sbomParser.SetupSequence(p => p.Next())
            .Returns(new FilesResult(new ParserStateResult(SPDXParser.FilesProperty, GetSpdxFiles(GetSpdxFilesDictionary()), ExplicitField: true, YieldReturn: true)))
            .Returns((ParserStateResult?)null);

        manifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>()))
            .Returns(sbomParser.Object);
        manifestParserProvider.Setup(m => m.Get(It.IsAny<ManifestInfo>())).Returns(manifestInterface.Object);

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
        configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
        configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { Constants.SPDX22ManifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = Constants.SPDX22ManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/spdx_2.2/manifest.spdx.json",
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(Constants.SPDX22ManifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead("/root/_manifest/spdx_2.2/manifest.spdx.json")).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

        fileSystemUtilsExtensionMock.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns((string fileName, AlgorithmName[] algos) =>
                new Checksum[]
                {
                    new Checksum
                    {
                        ChecksumValue = $"{fileName}hash",
                        Algorithm = Constants.DefaultHashAlgorithmName
                    }
                });

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.Is<string>(a => a == "/root/child2/grandchild1/file10"),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Throws(new FileNotFoundException());

        var fileHasher = new FileHasher(
            hashCodeGeneratorMock.Object,
            new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemUtilsExtensionMock.Object),
            mockLogger.Object,
            configurationMock.Object,
            new Mock<ISbomConfigProvider>().Object,
            new ManifestGeneratorProvider(null),
            new FileTypeUtils());

        var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, mockOSUtils.Object);
        manifestFilterMock.Init();
        var fileFilterer = new ManifestFolderFilterer(manifestFilterMock, mockLogger.Object);

        var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
        rootFileFilterMock.Init();

        var hashValidator = new ConcurrentSha256HashValidator(FileHashesDictionarySingleton.Instance);
        var enumeratorChannel = new EnumeratorChannel(mockLogger.Object);
        var fileConverter = new SbomFileToFileInfoConverter(new FileTypeUtils());
        var spdxFileFilterer = new FileFilterer(rootFileFilterMock, mockLogger.Object, configurationMock.Object, fileSystemMock.Object);

        var filesValidator = new FilesValidator(
            directoryWalker,
            configurationMock.Object,
            mockLogger.Object,
            fileHasher,
            fileFilterer,
            hashValidator,
            enumeratorChannel,
            fileConverter,
            FileHashesDictionarySingleton.Instance,
            spdxFileFilterer);

        var validator = new SbomParserBasedValidationWorkflow(
            recorder.Object,
            signValidationProviderMock.Object,
            mockLogger.Object,
            manifestParserProvider.Object,
            configurationMock.Object,
            sbomConfigs.Object,
            filesValidator,
            validationResultGenerator,
            outputWriterMock.Object,
            fileSystemMock.Object);

        var result = await validator.RunAsync();
        Assert.IsFalse(result);
        var nodeValidationResults = validationResultGenerator.NodeValidationResults;

        var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
        Assert.AreEqual(1, additionalFileErrors.Count);
        Assert.AreEqual("./child2/grandchild1/file7", additionalFileErrors.First().Path);

        var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
        Assert.AreEqual(1, missingFileErrors.Count);
        Assert.AreEqual("./child2/grandchild2/file10", missingFileErrors.First().Path);

        var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
        Assert.AreEqual(1, invalidHashErrors.Count);
        Assert.AreEqual("./child2/grandchild1/file9", invalidHashErrors.First().Path);

        var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
        Assert.AreEqual(1, otherErrors.Count);
        Assert.AreEqual("./child2/grandchild1/file10", otherErrors.First().Path);

        configurationMock.VerifyAll();
        signValidatorMock.VerifyAll();
        fileSystemMock.VerifyAll();
    }
}
