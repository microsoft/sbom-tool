// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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
using Microsoft.Sbom.Common.ConformanceStandard;
using Microsoft.Sbom.Common.ConformanceStandard.Enums;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
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
    private const string CaseSensitiveMessageMarker = "case-sensitive";

    private readonly Mock<ILogger> mockLogger = new();
    private readonly Mock<IOSUtils> mockOSUtils = new();
    private readonly Mock<IFileSystemUtilsExtension> fileSystemUtilsExtensionMock = new();
    private readonly Mock<ISignValidator> signValidatorMock = new();
    private readonly Mock<ISignValidationProvider> signValidationProviderMock = new();

    private const string SPDX22ManifestInfoJsonFilePath = "/root/_manifest/spdx_2.2/manifest.spdx.json";
    private const string SPDX30ManifestInfoJsonFilePath = "/root/_manifest/spdx_3.0/manifest.spdx.json";

    [TestInitialize]
    public void Init()
    {
        signValidatorMock.Setup(s => s.Validate(It.IsAny<IDictionary<string, string>>())).Returns(true);
        signValidationProviderMock.Setup(s => s.Get()).Returns(signValidatorMock.Object);
    }

    [TestCleanup]
    public void Reset()
    {
        FileHashesDictionarySingleton.Reset();
    }

    [DataRow(SPDX22ManifestInfoJsonFilePath)]
    [DataRow(SPDX30ManifestInfoJsonFilePath)]
    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsSuccessAndValidationFailures_IgnoreMissingTrue_Succeeds(string manifestInfoJsonFilePath)
    {
        var manifestInfo = manifestInfoJsonFilePath.Contains("2.2") ? Constants.SPDX22ManifestInfo : Constants.SPDX30ManifestInfo;

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
            Value = new List<ManifestInfo>() { manifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = manifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = manifestInfoJsonFilePath,
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(manifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead(manifestInfoJsonFilePath)).Returns(Stream.Null);
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

        var osUtilsMock = new Mock<IOSUtils>(MockBehavior.Strict);

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
            fileSystemMock.Object,
            osUtilsMock.Object);

        var cc = new ConsoleCapture();

        try
        {
            var result = await validator.RunAsync();
            Assert.IsTrue(result);
        }
        finally
        {
            cc.Restore();
        }

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

        Assert.IsFalse(cc.CapturedStdOut.Contains(CaseSensitiveMessageMarker), "Case-sensitive marker should not have been output");

        configurationMock.VerifyAll();
        signValidatorMock.VerifyAll();
        fileSystemMock.VerifyAll();
        osUtilsMock.VerifyAll();
        recorder.Verify(r => r.AddResult(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [DataRow(SPDX22ManifestInfoJsonFilePath)]
    [DataRow(SPDX30ManifestInfoJsonFilePath)]
    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsSuccessAndValidationFailures_Succeeds(string manifestInfoJsonFilePath)
    {
        const string key1 = "key1";
        const string key2 = "key2";
        const string value1 = "value1";
        const string value2 = "value2";

        signValidatorMock
            .Setup(s => s.Validate(It.IsAny<IDictionary<string, string>>()))
            .Returns(true)
            .Callback<IDictionary<string, string>>(additionalTelemetry =>
            {
                additionalTelemetry.Add(key1, value1);
                additionalTelemetry.Add(key2, value2);
            });
        var manifestInfo = manifestInfoJsonFilePath.Contains("2.2") ? Constants.SPDX22ManifestInfo : Constants.SPDX30ManifestInfo;

        var manifestParserProvider = new Mock<IManifestParserProvider>();
        var manifestInterface = new Mock<IManifestInterface>();
        var sbomParser = new Mock<ISbomParser>();
        var configurationMock = new Mock<IConfiguration>();
        var sbomConfigs = new Mock<ISbomConfigProvider>();
        var fileSystemMock = GetDefaultFileSystemMock();
        var outputWriterMock = new Mock<IOutputWriter>();
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        var recorder = new Mock<IRecorder>();
        recorder.Setup(r => r.AddResult(key1, value1));
        recorder.Setup(r => r.AddResult(key2, value2));

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
            Value = new List<ManifestInfo>() { manifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = manifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = manifestInfoJsonFilePath,
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(manifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead(manifestInfoJsonFilePath)).Returns(Stream.Null);
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

        var osUtilsMock = new Mock<IOSUtils>(MockBehavior.Strict);
        osUtilsMock.Setup(x => x.IsCaseSensitiveOS()).Returns(false);

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
            fileSystemMock.Object,
            osUtilsMock.Object);

        var cc = new ConsoleCapture();

        try
        {
            var result = await validator.RunAsync();
            Assert.IsFalse(result);
        }
        finally
        {
            cc.Restore();
        }

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

        Assert.IsTrue(cc.CapturedStdOut.Contains(CaseSensitiveMessageMarker), "Case-sensitive marker should have been output");

        configurationMock.VerifyAll();
        signValidatorMock.VerifyAll();
        fileSystemMock.VerifyAll();
        osUtilsMock.VerifyAll();
        recorder.VerifyAll();
    }

    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsNTIAValidationFailures_Succeeds()
    {
        var manifestInfo = Constants.SPDX30ManifestInfo;
        var manifestParserProvider = new Mock<IManifestParserProvider>();
        var manifestInterface = new Mock<IManifestInterface>();
        var sbomParser = new Mock<ISbomParser>();
        var configurationMock = new Mock<IConfiguration>();
        var sbomConfigs = new Mock<ISbomConfigProvider>();
        var fileSystemMock = GetDefaultFileSystemMock();
        var outputWriterMock = new Mock<IOutputWriter>();
        var recorder = new Mock<IRecorder>();
        var osUtilsMock = new Mock<IOSUtils>(MockBehavior.Strict);
        osUtilsMock.Setup(x => x.IsCaseSensitiveOS()).Returns(false);

        manifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>()))
            .Returns(sbomParser.Object);
        manifestParserProvider.Setup(m => m.Get(It.IsAny<ManifestInfo>())).Returns(manifestInterface.Object);

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
        configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
        configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { manifestInfo }
        });
        configurationMock.SetupGet(c => c.ConformanceStandard).Returns(new ConfigurationSetting<ConformanceStandardType> { Value = ConformanceStandardType.NTIA });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = manifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = SPDX30ManifestInfoJsonFilePath,
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(manifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead(SPDX30ManifestInfoJsonFilePath)).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var filesValidator = GetFilesValidator(fileSystemMock, configurationMock);

        var elementsResult = new ElementsResult(new ParserStateResult(Constants.SPDXGraphHeaderName, null, ExplicitField: true, YieldReturn: true));

        elementsResult.InvalidConformanceStandardElements.Add(new InvalidElementInfo(NTIAErrorType.MissingValidSpdxDocument));
        elementsResult.InvalidConformanceStandardElements.Add(new InvalidElementInfo("spdxDocElementName", "spdxDocElementSpdxId", NTIAErrorType.AdditionalSpdxDocument));
        elementsResult.InvalidConformanceStandardElements.Add(new InvalidElementInfo(NTIAErrorType.MissingValidCreationInfo));
        elementsResult.InvalidConformanceStandardElements.Add(new InvalidElementInfo("elementName", "elementSpdxId", NTIAErrorType.InvalidNTIAElement));

        sbomParser.SetupSequence(p => p.Next()).Returns(elementsResult);

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
            fileSystemMock.Object,
            osUtilsMock.Object);

        var cc = new ConsoleCapture();

        try
        {
            var result = await validator.RunAsync();
            Assert.IsFalse(result);
        }
        finally
        {
            cc.Restore();
        }

        var nodeValidationResults = validationResultGenerator.NodeValidationResults;

        var ntiaErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.ConformanceStandardError).ToList();
        Assert.AreEqual(4, ntiaErrors.Count);

        Assert.AreEqual("MissingValidSpdxDocument", ntiaErrors.First().Path);
        Assert.AreEqual("AdditionalSpdxDocument. SpdxId: spdxDocElementSpdxId. Name: spdxDocElementName", ntiaErrors[1].Path);
        Assert.AreEqual("MissingValidCreationInfo", ntiaErrors[2].Path);
        Assert.AreEqual("SpdxId: elementSpdxId. Name: elementName", ntiaErrors[3].Path);

        Assert.IsTrue(cc.CapturedStdOut.Contains("Elements in the manifest that are non-compliant with NTIA . . . 4"), "Number of invalid NTIA elements is incorrect in stdout");
        Assert.IsTrue(cc.CapturedStdOut.Contains("MissingValidSpdxDocument"));
        Assert.IsTrue(cc.CapturedStdOut.Contains("AdditionalSpdxDocument. SpdxId: spdxDocElementSpdxId. Name: spdxDocElementName"));
        Assert.IsTrue(cc.CapturedStdOut.Contains("MissingValidCreationInfo"));
        Assert.IsTrue(cc.CapturedStdOut.Contains("SpdxId: elementSpdxId. Name: elementName"));

        configurationMock.VerifyAll();
    }

    private FilesValidator GetFilesValidator(Mock<IFileSystemUtils> fileSystemMock, Mock<IConfiguration> configurationMock)
    {
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

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

        return filesValidator;
    }
}
