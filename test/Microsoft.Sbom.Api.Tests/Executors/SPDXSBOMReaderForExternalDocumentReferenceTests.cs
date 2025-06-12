// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Executors;

[TestClass]
public class SPDXSBOMReaderForExternalDocumentReferenceTests
{
    private readonly Mock<IHashCodeGenerator> mockHashGenerator = new Mock<IHashCodeGenerator>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IConfiguration> mockConfiguration = new Mock<IConfiguration>();
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>();
    private readonly Mock<ISbomReferenceFactory> sbomReferenceFactory = new Mock<ISbomReferenceFactory>();

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

        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 }; // or whatever is appropriate
        var spdx22SbomReference = new Spdx22SbomReference(
            mockHashGenerator.Object,
            fileSystemMock.Object,
            hashAlgorithmNames);

        // Setup the mock to return the real instance
        sbomReferenceFactory.Setup(f => f.GetSbomReferenceDescriber(It.IsAny<string>())).Returns(spdx22SbomReference);
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

        var json = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(json));

        var sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSbomReaderForExternalDocumentReference(mockLogger.Object, sbomReferenceFactory.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSbomFile(sbomLocationChannel);
        await foreach (var externalDocumentReferenceInfo in output.ReadAllAsync())
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
        var json = "{\"name\": ,\"documentNamespace\": \"namespace\"}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(json));

        var sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSbomReaderForExternalDocumentReference(mockLogger.Object, sbomReferenceFactory.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSbomFile(sbomLocationChannel);

        Assert.IsTrue(await errors.ReadAllAsync().AnyAsync());
        Assert.IsFalse(await output.ReadAllAsync().AnyAsync());
    }

    [TestMethod]
    public async Task When_ParseSBOMFile_WithNonSPDXFile_ThenDoNotReadFiles()
    {
        var nonSpdxSbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in nonSpdxSbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSbomReaderForExternalDocumentReference(mockLogger.Object, sbomReferenceFactory.Object);
        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSbomFile(sbomLocationChannel);

        mockHashGenerator.VerifyNoOtherCalls();
        fileSystemMock.VerifyNoOtherCalls();
        sbomReferenceFactory.VerifyNoOtherCalls();

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

        var sbomLocations = new List<string>
        {
            @"d:\directorya\directoryb\file1.spdx.json"
        };

        var sbomLocationChannel = Channel.CreateUnbounded<string>();
        foreach (var sbomLocation in sbomLocations)
        {
            await sbomLocationChannel.Writer.WriteAsync(sbomLocation);
        }

        sbomLocationChannel.Writer.Complete();

        var spdxSBOMReaderForExternalDocumentReference = new SPDXSbomReaderForExternalDocumentReference(mockLogger.Object, sbomReferenceFactory.Object);

        var (output, errors) = spdxSBOMReaderForExternalDocumentReference.ParseSbomFile(sbomLocationChannel);

        Assert.IsTrue(await errors.ReadAllAsync().AnyAsync());
        Assert.IsFalse(await output.ReadAllAsync().AnyAsync());
    }

    [TestMethod]
    public void Spdx22SbomReference_IsSupportedFormat_ReturnsTrueForValidSpdx22()
    {
        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 };
        var validJson = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(validJson));

        var sbomReference = new Spdx22SbomReference(mockHashGenerator.Object, fileSystemMock.Object, hashAlgorithmNames);

        var result = sbomReference.IsSupportedFormat("file.spdx.json");
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void Spdx22SbomReference_IsSupportedFormat_ReturnsFalseForInvalidSpdx22Version()
    {
        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 };
        var invalidJson = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.1\", \"documentDescribes\":[\"SPDXRef - RootPackage\"]}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(invalidJson));
        var sbomReference = new Spdx22SbomReference(mockHashGenerator.Object, fileSystemMock.Object, hashAlgorithmNames);

        var result = sbomReference.IsSupportedFormat("file.spdx.json");
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void Spdx22SbomReference_IsSupportedFormat_ReturnsFalseForMissingSpdx22Version()
    {
        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 };
        var invalidJson = JsonMissingVersion;
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(invalidJson));
        var sbomReference = new Spdx22SbomReference(mockHashGenerator.Object, fileSystemMock.Object, hashAlgorithmNames);

        var result = sbomReference.IsSupportedFormat("file.spdx.json");
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void SbomReferenceFactory_ReturnsCorrectDescriber()
    {
        var describerMock1 = new Mock<ISbomReferenceDescriber>();
        var describerMock2 = new Mock<ISbomReferenceDescriber>();
        describerMock1.Setup(d => d.IsSupportedFormat(It.IsAny<string>())).Returns(false);
        describerMock2.Setup(d => d.IsSupportedFormat(It.IsAny<string>())).Returns(true);

        var factory = new SbomReferenceFactory(new List<ISbomReferenceDescriber> { describerMock1.Object, describerMock2.Object });

        var result = factory.GetSbomReferenceDescriber("file.spdx.json");
        Assert.AreSame(describerMock2.Object, result);
    }

    [TestMethod]
    public void SbomReferenceFactory_ReturnsNullIfNoDescriberSupports()
    {
        var describerMock1 = new Mock<ISbomReferenceDescriber>();
        var describerMock2 = new Mock<ISbomReferenceDescriber>();
        describerMock1.Setup(d => d.IsSupportedFormat(It.IsAny<string>())).Returns(false);
        describerMock2.Setup(d => d.IsSupportedFormat(It.IsAny<string>())).Returns(false);

        var factory = new SbomReferenceFactory(new List<ISbomReferenceDescriber> { describerMock1.Object, describerMock2.Object });

        var result = factory.GetSbomReferenceDescriber("file.spdx.json");
        Assert.IsNull(result);
    }

    [DataRow(JsonMissingName)]
    [DataRow(JsonMissingNamespace)]
    [DataRow(JsonMissingVersion)]
    [DataRow(JsonInvalidVersion)]
    [DataRow(JsonMissingDocumentDescribe)]
    [TestMethod]
    public void Spdx22SbomReference_ExtractDocRefInfo_ThrowsForMissingProperty(string jsonInput)
    {
        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 };
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(jsonInput));
        var sbomReference = new Spdx22SbomReference(mockHashGenerator.Object, fileSystemMock.Object, hashAlgorithmNames);

        Assert.ThrowsException<Exception>(() => sbomReference.CreateExternalDocumentRefererence("file.spdx.json"));
    }

    [TestMethod]
    public void Spdx22SbomReference_ExtractDocRefInfo_ForSpdx22_ReturnsObjectIfSuccess()
    {
        var hashAlgorithmNames = new[] { AlgorithmName.SHA256 };
        var validJson = "{\"name\": \"docname\",\"documentNamespace\": \"namespace\", \"spdxVersion\": \"SPDX-2.2\", \"documentDescribes\":[\"SPDXRef-RootPackage\"]}";
        fileSystemMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(validJson));
        var sbomReference = new Spdx22SbomReference(mockHashGenerator.Object, fileSystemMock.Object, hashAlgorithmNames);

        var docRef = sbomReference.CreateExternalDocumentRefererence("file.spdx.json");
        Assert.IsNotNull(docRef);
        Assert.AreEqual("docname", docRef.ExternalDocumentName, true);
        Assert.AreEqual("namespace", docRef.DocumentNamespace, true);
        Assert.AreEqual("SPDXRef-RootPackage", docRef.DescribedElementID, true);

        // Need unit test for Checksums
    }
}
