// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
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
public class FileInfoWriterTests
{
    private Mock<ILogger> loggerMock;
    private Mock<ISbomConfig> sbomConfigMock;
    private Mock<ISbomPackageDetailsRecorder> sbomPackageDetailsRecorderMock;
    private Mock<IManifestToolJsonSerializer> manifestToolJsonSerializerMock;
    private FileInfoWriter testSubject;
    private ManifestGeneratorProvider manifestGeneratorProvider;

    [TestInitialize]
    public void BeforeEach()
    {
        loggerMock = new Mock<ILogger>();
        sbomPackageDetailsRecorderMock = new Mock<ISbomPackageDetailsRecorder>();
        manifestToolJsonSerializerMock = new Mock<IManifestToolJsonSerializer>();

        manifestGeneratorProvider = new ManifestGeneratorProvider(new IManifestGenerator[] { new TestManifestGenerator() });
        manifestGeneratorProvider.Init();

        testSubject = new FileInfoWriter(manifestGeneratorProvider, loggerMock.Object);

        sbomConfigMock = new Mock<ISbomConfig>();
        sbomConfigMock.SetupGet(x => x.ManifestInfo).Returns(Constants.TestManifestInfo);
        sbomConfigMock.SetupGet(x => x.Recorder).Returns(sbomPackageDetailsRecorderMock.Object);
        sbomConfigMock.SetupGet(x => x.JsonSerializer).Returns(manifestToolJsonSerializerMock.Object);
    }

    [TestCleanup]
    public void AfterEach()
    {
        // Just verify nothing throws
    }

    [TestMethod]
    public async Task Write_FileWithinDropPath_WritesToFilesSection()
    {
        // Arrange
        var sbomConfigs = new[] { sbomConfigMock.Object };
        var fileInfo = new InternalSbomFileInfo
        {
            Path = "internal/package.spdx.json",
            IsOutsideDropPath = false,
            FileTypes = new[] { FileType.SPDX },
            Checksum = new[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "abc123" } }
        };

        var fileInfoChannel = Channel.CreateUnbounded<InternalSbomFileInfo>();
        await fileInfoChannel.Writer.WriteAsync(fileInfo);
        fileInfoChannel.Writer.Complete();

        // Setup expectations - SPDX files within drop path should record both types of IDs
        sbomPackageDetailsRecorderMock.Setup(m => m.RecordFileId(It.IsAny<string>()));
        sbomPackageDetailsRecorderMock.Setup(m => m.RecordSPDXFileId(It.IsAny<string>()));

        // Act
        var (result, errors) = testSubject.Write(fileInfoChannel.Reader, sbomConfigs);

        // Assert
        var resultList = new List<JsonDocWithSerializer>();
        await foreach (var item in result.ReadAllAsync())
        {
            resultList.Add(item);
        }

        var errorList = new List<FileValidationResult>();
        await foreach (var error in errors.ReadAllAsync())
        {
            errorList.Add(error);
        }

        // Verify file was written to files section
        Assert.AreEqual(1, resultList.Count);
        Assert.AreEqual(0, errorList.Count);
    }

    [TestMethod]
    public async Task Write_FileOutsideDropPath_DoesNotWriteToFilesSection()
    {
        // Arrange
        var sbomConfigs = new[] { sbomConfigMock.Object };
        var fileInfo = new InternalSbomFileInfo
        {
            Path = "external/package.spdx.json",
            IsOutsideDropPath = true,
            FileTypes = new[] { FileType.SPDX },
            Checksum = new[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "def456" } }
        };

        var fileInfoChannel = Channel.CreateUnbounded<InternalSbomFileInfo>();
        await fileInfoChannel.Writer.WriteAsync(fileInfo);
        fileInfoChannel.Writer.Complete();

        // Setup expectations - SPDX file ID should still be recorded
        sbomPackageDetailsRecorderMock.Setup(m => m.RecordSPDXFileId(It.IsAny<string>()));

        // Act
        var (result, errors) = testSubject.Write(fileInfoChannel.Reader, sbomConfigs);

        // Assert
        var resultList = new List<JsonDocWithSerializer>();
        await foreach (var item in result.ReadAllAsync())
        {
            resultList.Add(item);
        }

        var errorList = new List<FileValidationResult>();
        await foreach (var error in errors.ReadAllAsync())
        {
            errorList.Add(error);
        }

        // Verify file was NOT written to files section
        Assert.AreEqual(0, resultList.Count);
        Assert.AreEqual(0, errorList.Count);
    }
}
