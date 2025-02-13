// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;
using SpdxChecksum = Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Checksum;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

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

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    private readonly string sbomMetadataJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            },
            {
            ""name"": ""./sample/path"",
            ""software_copyrightText"": ""sampleCopyright"",
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
            ""verifiedUsing"": [
              {
                ""algorithm"": ""sha1"",
                ""hashValue"": ""sha1value"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                ""type"": ""PackageVerificationCode""
              },
              {
                ""algorithm"": ""sha256"",
                ""hashValue"": ""sha256value"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-PackageVerificationCode-5D5B09F6DCB2D53A5FFFC60C4AC0D55FABDF556069D6631545F42AA6E3500F2E"",
                ""type"": ""PackageVerificationCode""
              }
            ],
            ""type"": ""software_File""
          }   
        ]
    }
    ";

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
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = SpdxConstants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { SpdxConstants.SPDX22ManifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = SpdxConstants.SPDX22ManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/spdx_2.2/manifest.spdx.json",
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(SpdxConstants.SPDX22ManifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead("/root/_manifest/spdx_2.2/manifest.spdx.json")).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

        fileSystemUtilsExtensionMock.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { SpdxConstants.DefaultHashAlgorithmName }))
            .Returns((string fileName, AlgorithmName[] algos) =>
                new Checksum[]
                {
                    new Checksum
                    {
                        ChecksumValue = $"{fileName}hash",
                        Algorithm = SpdxConstants.DefaultHashAlgorithmName
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
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = SpdxConstants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { SpdxConstants.SPDX22ManifestInfo }
        });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = SpdxConstants.SPDX22ManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/spdx_2.2/manifest.spdx.json",
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };
        sbomConfigs.Setup(c => c.Get(SpdxConstants.SPDX22ManifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead("/root/_manifest/spdx_2.2/manifest.spdx.json")).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

        fileSystemUtilsExtensionMock.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { SpdxConstants.DefaultHashAlgorithmName }))
            .Returns((string fileName, AlgorithmName[] algos) =>
                new Checksum[]
                {
                    new Checksum
                    {
                        ChecksumValue = $"{fileName}hash",
                        Algorithm = SpdxConstants.DefaultHashAlgorithmName
                    }
                });

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.Is<string>(a => a == "/root/child2/grandchild1/file10"),
                new AlgorithmName[] { SpdxConstants.DefaultHashAlgorithmName }))
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
    }

    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_SetsComplianceStandard_Succeeds()
    {
        var bytes = Encoding.UTF8.GetBytes(sbomMetadataJsonString);
        using var stream = new MemoryStream(bytes);

        var mockSpdx30Parser = new SPDX30Parser(stream);

        var manifestParserProvider = new Mock<IManifestParserProvider>();
        var manifestInterface = new Mock<IManifestInterface>();
        var configurationMock = new Mock<IConfiguration>();
        var sbomConfigs = new Mock<ISbomConfigProvider>();
        var fileSystemMock = new Mock<IFileSystemUtils>();
        var outputWriterMock = new Mock<IOutputWriter>();
        var recorder = new Mock<IRecorder>();
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();

        manifestInterface.Setup(m => m.CreateParser(It.IsAny<Stream>()))
            .Returns(mockSpdx30Parser);
        manifestParserProvider.Setup(m => m.Get(It.IsAny<ManifestInfo>())).Returns(manifestInterface.Object);

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
        configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
        configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = SpdxConstants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo>() { SpdxConstants.SPDX30ManifestInfo }
        });
        configurationMock.SetupGet(c => c.ComplianceStandard).Returns(new ConfigurationSetting<string> { Value = "NTIA" });

        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = SpdxConstants.SPDX30ManifestInfo,
            ManifestJsonDirPath = "/root/_manifest",
            ManifestJsonFilePath = "/root/_manifest/spdx_3.0/manifest.spdx.json",
            MetadataBuilder = null,
            Recorder = new SbomPackageDetailsRecorder()
        };

        sbomConfigs.Setup(c => c.Get(SpdxConstants.SPDX30ManifestInfo)).Returns(sbomConfig);

        fileSystemMock.Setup(f => f.OpenRead("/root/_manifest/spdx_3.0/manifest.spdx.json")).Returns(Stream.Null);
        fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string root, string relativePath) => $"{root}/{relativePath}");
        fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>()))
            .Returns(true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

        var directoryWalker = new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object);

        hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { SpdxConstants.DefaultHashAlgorithmName }))
            .Returns((string fileName, AlgorithmName[] algos) =>
                new Checksum[]
                {
                    new Checksum
                    {
                        ChecksumValue = $"{fileName}hash",
                        Algorithm = SpdxConstants.DefaultHashAlgorithmName
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
            Assert.AreEqual("NTIA", mockSpdx30Parser.RequiredComplianceStandard);
        }
        finally
        {
            cc.Restore();
        }

        configurationMock.VerifyAll();
        signValidatorMock.VerifyAll();
        fileSystemMock.VerifyAll();
        osUtilsMock.VerifyAll();
    }
}
