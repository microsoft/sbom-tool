// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Executors;

[TestClass]
public class SPDXSBOMReaderForExternalDocumentReferenceTests
{
    private readonly Mock<IHashCodeGenerator> mockHashGenerator = new Mock<IHashCodeGenerator>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly Mock<IConfiguration> mockConfiguration = new Mock<IConfiguration>();
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>();

    private const string JsonMissingName = "{\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
    private const string JsonMissingNamespace = "{\"name\": \"docname\",\"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
    private const string JsonMissingVersion = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\",\"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
    private const string JsonInvalidVersion = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.1\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
    private const string JsonMissingDocumentDescribe = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\"}";

    public SPDXSBOMReaderForExternalDocumentReferenceTests()
    {
        mockConfiguration.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        mockConfiguration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
        mockConfiguration.SetupGet(c => c.BuildComponentPath).Returns(new ConfigurationSetting<string> { Value = "root" });

        manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        manifestGeneratorProvider.Init();

        var sbomConfigsMock = new Mock<ISbomConfigProvider>();
        sbomConfigsMock.Setup(c => c.GetManifestInfos()).Returns(new[] { new ManifestInfo { Name = "TestManifest", Version = "1.0.0" } });
        sbomConfigs = sbomConfigsMock.Object;
    }

    [TestMethod]
    public async Task When_ParseSBOMFile_WithValidSPDXJson_ThenTestPass()
    {
        mockHashGenerator.Setup(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()))
            .Returns((string fileName, AlgorithmName[] algos) =>
                algos.Select(a =>
                        new Checksum
                        {
                            ChecksumValue = "hash",
                            Algorithm = a
                        })
                    .ToArray());

        string json = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(json));

        List<string> sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSBOMReaderForExternalDocumentReference(mockHashGenerator.Object, mockLogger.Object, sbomConfigs, manifestGeneratorProvider, fileSystemMock.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSBOMFile(sbomLocationChannel);
        await foreach (ExternalDocumentReferenceInfo externalDocumentReferenceInfo in output.ReadAllAsync())
        {
            Assert.AreEqual("namespace", externalDocumentReferenceInfo.DocumentNamespace);
        }

        Assert.IsFalse(await errors.ReadAllAsync().AnyAsync());
    }

    [TestMethod]
    public async Task When_ParseSBOMFile_WithIllFormatedJson_ThenReadAsyncFail()
    {
        mockHashGenerator.Setup(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()))
            .Returns((string fileName, AlgorithmName[] algos) =>
                algos.Select(a =>
                        new Checksum
                        {
                            ChecksumValue = "hash",
                            Algorithm = a
                        })
                    .ToArray());
        string json = "{\"name\": ,\"documentNamespace\": \"namespace\"}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(json));

        List<string> sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSBOMReaderForExternalDocumentReference(mockHashGenerator.Object, mockLogger.Object, sbomConfigs, manifestGeneratorProvider, fileSystemMock.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSBOMFile(sbomLocationChannel);

        Assert.IsTrue(await errors.ReadAllAsync().AnyAsync());
        Assert.IsFalse(await output.ReadAllAsync().AnyAsync());
    }

    [TestMethod]
    public async Task When_ParseSBOMFile_WithNonSPDXFile_ThenDoNotReadFiles()
    {
        List<string> nonSpdxSbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in nonSpdxSbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSBOMReaderForExternalDocumentReference(mockHashGenerator.Object, mockLogger.Object, sbomConfigs, manifestGeneratorProvider, fileSystemMock.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSBOMFile(sbomLocationChannel);

        mockHashGenerator.VerifyNoOtherCalls();
        fileSystemMock.VerifyNoOtherCalls();

        Assert.IsFalse(await errors.ReadAllAsync().AnyAsync());
        Assert.IsFalse(await output.ReadAllAsync().AnyAsync());
    }

    [TestMethod]
    [DataRow(JsonMissingName)]
    [DataRow(JsonMissingNamespace)]
    [DataRow(JsonMissingVersion)]
    [DataRow(JsonInvalidVersion)]
    [DataRow(JsonMissingDocumentDescribe)]
    public async Task When_ParseSBOMFile_WithSPDXDocumentIssues_ThenThrowException(string inputJson)
    {
        mockHashGenerator.Setup(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()))
            .Returns((string fileName, AlgorithmName[] algos) =>
                algos.Select(a =>
                        new Checksum
                        {
                            ChecksumValue = "hash",
                            Algorithm = a
                        })
                    .ToArray());

        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(inputJson));

        List<string> sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSBOMReaderForExternalDocumentReference(mockHashGenerator.Object, mockLogger.Object, sbomConfigs, manifestGeneratorProvider, fileSystemMock.Object);

        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSBOMFile(sbomLocationChannel);

        Assert.IsTrue(await errors.ReadAllAsync().AnyAsync());
        Assert.IsFalse(await output.ReadAllAsync().AnyAsync());
    }
}