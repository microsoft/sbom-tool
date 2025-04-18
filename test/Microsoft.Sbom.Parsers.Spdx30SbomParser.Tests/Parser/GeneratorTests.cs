// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parser.JsonStrings;
using Microsoft.Sbom.Parsers.Spdx30SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Constants = Microsoft.Sbom.Parsers.Spdx30SbomParser.Constants;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class GeneratorTests
{
    private readonly Generator generator = new Generator();
    private readonly Mock<IRecorder> recorderMock = new Mock<IRecorder>(MockBehavior.Strict);
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>(MockBehavior.Strict);
    private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
    private readonly Mock<IManifestConfigHandler> mockConfigHandler = new Mock<IManifestConfigHandler>(MockBehavior.Strict);

    [TestMethod]
    public void GenerateJsonDocumentTest_DocumentCreation()
    {
        var sbomConfigs = CreateInternalMetadataProvider();
        var generatorResult = generator.GenerateJsonDocument(sbomConfigs);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomDocCreationJsonStrings.DocCreationJsonString;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);
        var regexPattern = ConvertJsonToRegex(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.IsTrue(Regex.IsMatch(generatedJsonString, regexPattern));
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_RootPackage()
    {
        var sbomConfigs = CreateInternalMetadataProvider();

        var generatorResult = generator.GenerateRootPackage(sbomConfigs);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomPackageJsonStrings.RootPackageJsonString;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);
        var regexPattern = ConvertJsonToRegex(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.IsTrue(Regex.IsMatch(generatedJsonString, regexPattern), $"Unexpected output: {generatedJsonString}");
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_Package()
    {
        var packageInfo = new SbomPackage
        {
            PackageName = "test",
            PackageUrl = "packageUrl",
            FilesAnalyzed = false
        };

        var generatorResult = generator.GenerateJsonDocument(packageInfo);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomPackageJsonStrings.PackageWithNoAssertionAndPurlJsonString;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.AreEqual(expectedJsonContentAsString, generatedJsonString);
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_Null_ReturnsNull()
    {
        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = null
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.IsNull(result.ResultMetadata.DependOn, "DependOnId should be null when DependOn is null.");
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_EqualsRootPackageId_ReturnsRootPackageId()
    {
        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = Constants.RootPackageIdValue
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        Assert.AreEqual(Constants.RootPackageIdValue, result.ResultMetadata.DependOn, "DependOnId should equal RootPackageId when DependOn is RootPackageId.");
    }

    [TestMethod]
    public void GenerateJsonDocument_DependsOnId_ValidValue_GeneratesSpdxPackageId()
    {
        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            DependOn = "SomePackageId"
        };

        var result = generator.GenerateJsonDocument(packageInfo);

        var expectedDependOnId = CommonSPDXUtils.GenerateSpdxPackageId("SomePackageId");
        Assert.AreEqual(expectedDependOnId, result.ResultMetadata.DependOn, "DependOnId should be correctly generated using CommonSPDXUtils.GenerateSpdxPackageId.");
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_File()
    {
        var fileInfo = new InternalSbomFileInfo
        {
            Checksum = GetSampleChecksums(),
            FileCopyrightText = "sampleCopyright",
            LicenseConcluded = "sampleLicense1",
            LicenseInfoInFiles = new List<string> { "sampleLicense1" },
            Path = "./sample/path",
        };

        var generatorResult = generator.GenerateJsonDocument(fileInfo);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomFileJsonStrings.FileWithLicensesAndHashes;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.AreEqual(expectedJsonContentAsString, generatedJsonString);
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_FilesWithDifferingChecksums_CreatesDifferentSpdxFiles()
    {
        var fileInfo1 = new InternalSbomFileInfo
        {
            Checksum = GetSampleChecksums(),
            FileCopyrightText = "sampleCopyright",
            LicenseConcluded = "sampleLicense1",
            LicenseInfoInFiles = new List<string> { "sampleLicense1" },
            Path = "/sample/path",
        };

        var fileInfo2 = new InternalSbomFileInfo
        {
            Checksum = GetDifferentSampleChecksums(),
            FileCopyrightText = "sampleCopyright",
            LicenseConcluded = "sampleLicense1",
            LicenseInfoInFiles = new List<string> { "sampleLicense1" },
            Path = "/sample/path",
        };

        var generatorResultFile1 = generator.GenerateJsonDocument(fileInfo1);
        var generatorResultFile2 = generator.GenerateJsonDocument(fileInfo2);

        // Compare entity IDs which is the same as the SPDX ID for each file.
        Assert.AreNotEqual(generatorResultFile1.ResultMetadata.EntityId, generatorResultFile2.ResultMetadata.EntityId);
        Assert.IsTrue(generatorResultFile1.ResultMetadata.EntityId.Contains("sha1Value"));
        Assert.IsTrue(generatorResultFile2.ResultMetadata.EntityId.Contains("DIFFsha1Value"));
        Assert.AreNotEqual(generatorResultFile1, generatorResultFile2);
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_ExternalMap()
    {
        var externalDocInfo = new ExternalDocumentReferenceInfo
        {
            DocumentNamespace = "sample-namespace",
            Checksum = GetSampleChecksums(),
            ExternalDocumentName = "sample-external-doc",
        };

        var generatorResult = generator.GenerateJsonDocument(externalDocInfo);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomExternalMapJsonStrings.ExternalMapJsonString;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.AreEqual(expectedJsonContentAsString, generatedJsonString);
    }

    [TestMethod]
    public void GenerateJsonDocumentTest_Relationship()
    {
        var relationshipInfo = new Relationship
        {
            SourceElementId = "source-id",
            TargetElementId = "target-id",
            RelationshipType = RelationshipType.DESCRIBES,
        };

        var generatorResult = generator.GenerateJsonDocument(relationshipInfo);
        var generatedJsonString = generatorResult.Document.RootElement.GetRawText();
        generatedJsonString = NormalizeString(generatedJsonString);

        var expectedJsonContentAsString = SbomRelationshipJsonStrings.RelationshipJsonString;
        expectedJsonContentAsString = NormalizeString(expectedJsonContentAsString);

        Assert.IsFalse(generatedJsonString.Contains("null"));
        Assert.AreEqual(expectedJsonContentAsString, generatedJsonString);
    }

    [TestCleanup]
    public void Cleanup()
    {
        recorderMock.VerifyAll();
        mockLogger.VerifyAll();
        fileSystemMock.VerifyAll();
        mockConfigHandler.VerifyAll();
    }

    private string NormalizeString(string input)
    {
        return input.Replace("\r", string.Empty)
                    .Replace("\n", string.Empty)
                    .Replace(" ", string.Empty);
    }

    private string ConvertJsonToRegex(string input)
    {
        var pattern = Regex.Escape(input);

        // Replace placeholders with appropriate regex patterns
        pattern = pattern.Replace(@"\.\*", ".*");
        return pattern;
    }

    private List<Checksum> GetSampleChecksums()
    {
        return new List<Checksum>
        {
          new Checksum
          {
            Algorithm = AlgorithmName.SHA1,
            ChecksumValue = "sha1Value"
          },  new Checksum
          {
            Algorithm = AlgorithmName.SHA256,
            ChecksumValue = "sha256Value"
          },
        };
    }

    private List<Checksum> GetDifferentSampleChecksums()
    {
        return new List<Checksum>
        {
          new Checksum
          {
            Algorithm = AlgorithmName.SHA1,
            ChecksumValue = "DIFFsha1Value"
          },  new Checksum
          {
            Algorithm = AlgorithmName.SHA256,
            ChecksumValue = "DIFFsha256Value"
          },
        };
    }

    private IInternalMetadataProvider CreateInternalMetadataProvider()
    {
        ISbomConfig sbomConfig = new SbomConfig(fileSystemMock.Object)
        {
            ManifestInfo = Constants.SPDX30ManifestInfo,
            Recorder = new SbomPackageDetailsRecorder()
        };

        mockConfigHandler.Setup(c => c.TryGetManifestConfig(out sbomConfig)).Returns(true);
        recorderMock.Setup(r => r.RecordSbomFormat(Constants.SPDX30ManifestInfo, It.IsAny<string>()));
        mockLogger.Setup(l => l.Debug(It.IsAny<string>()));

        var config = new Configuration
        {
            PackageName = new ConfigurationSetting<string>("the-package-name"),
            PackageVersion = new ConfigurationSetting<string>("the-package-version"),
            NamespaceUriUniquePart = new ConfigurationSetting<string>("some-custom-value-here"),
            NamespaceUriBase = new ConfigurationSetting<string>("http://sbom.microsoft"),
            PackageSupplier = new ConfigurationSetting<string>("the-package-supplier"),
        };

        var sbomMetadata = new SbomMetadata
        {
            PackageName = "sbom-package-name",
            PackageVersion = "sbom-package-version",
            BuildEnvironmentName = "the-build-envsdfgsdg",
        };

        var localMetadataProvider = new LocalMetadataProvider(config);

        var sbomApiMetadataProvider = new SbomApiMetadataProvider(sbomMetadata, config);
        var metadataProviders = new IMetadataProvider[] { localMetadataProvider, sbomApiMetadataProvider };
        IInternalMetadataProvider sbomConfigs = CreateSbomConfigs(metadataProviders);

        return sbomConfigs;
    }

    private ISbomConfigProvider CreateSbomConfigs(IMetadataProvider[] metadataProviders) =>
        new SbomConfigProvider(
            manifestConfigHandlers: new IManifestConfigHandler[] { mockConfigHandler.Object },
            metadataProviders: metadataProviders,
            logger: mockLogger.Object,
            recorder: recorderMock.Object);
}
