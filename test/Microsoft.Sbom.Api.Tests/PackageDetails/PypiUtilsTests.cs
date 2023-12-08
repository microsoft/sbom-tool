// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.PackageDetails;

[TestClass]
public class PypiUtilsTests
{
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();
    private readonly Mock<IProcessExecutor> mockProcessExecutor = new Mock<IProcessExecutor>();

    [TestMethod]
    public void GetMetadataLocation_WhenMetadataExists_ShouldReturnPath()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new PipComponent("sample-python-package", "1.0.0")
        };
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns("Location: python_base_path/site-packages");

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = pypiUtils.GetMetadataLocation(scannedComponent);
        Assert.IsTrue(result.EndsWith("metadata", System.StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void GetMetadataLocation_WhenMetadataDoesNotExist_ReturnsNull()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new PipComponent("sample-python-package", "1.0.0")
        };

        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns("Location: python_base_path/site-packages");
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(false);

        var result = pypiUtils.GetMetadataLocation(scannedComponent);
        Assert.IsNull(result);
    }

    [TestMethod]
    public void GetMetadataLocation_ExecuteCommandFails_ReturnsNull()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new PipComponent("sample-python-package", "1.0.0")
        };

        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns((string)null);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = pypiUtils.GetMetadataLocation(scannedComponent);
        Assert.IsNull(result);
    }

    [TestMethod]
    public void GetMetadataLocation_ExecuteCommandThrows_ReturnsNull()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new PipComponent("sample-python-package", "1.0.0")
        };

        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Throws(new System.Exception());
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = pypiUtils.GetMetadataLocation(scannedComponent);
        Assert.IsNull(result);
    }

    [TestMethod]
    public void ParseMetadata_WhenMetadataIsValid_SingleLicense()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var metadataContent = SampleMetadataFiles.PipMetadataValidAuthorAndSingleLicense;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(metadataContent);

        var parsedGemspecInfo = pypiUtils.ParseMetadata(metadataContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "BSD License");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, "Sample Author");
        Assert.AreEqual(parsedGemspecInfo.Name, "sample-python-package");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void ParseMetadata_WhenMetadataIsValid_MultipleLicenses()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var metadataContent = SampleMetadataFiles.PipMetadataValidAuthorAndDualLicense;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(metadataContent);

        var parsedGemspecInfo = pypiUtils.ParseMetadata(metadataContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "BSD License, Apache Software License");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, "Sample Author");
        Assert.AreEqual(parsedGemspecInfo.Name, "sample-python-package");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void ParseMetadata_WhenMetadataIsValid_MissingSupplierAndLicense()
    {
        var pypiUtils = new PypiUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var metadataContent = SampleMetadataFiles.PipMetadataMissingSupplierAndLicense;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(metadataContent);

        var parsedGemspecInfo = pypiUtils.ParseMetadata(metadataContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, null);
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, null);
        Assert.AreEqual(parsedGemspecInfo.Name, "sample-python-package");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }
}
