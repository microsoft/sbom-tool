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
public class RubyGemsUtilsTests
{
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();
    private readonly Mock<IProcessExecutor> mockProcessExecutor = new Mock<IProcessExecutor>();

    [TestMethod]
    public void ParseValidGemspec_PopulatesSupplierAndMultipleLicenses()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var gemspecContent = SampleMetadataFiles.GemspecWithValidAuthorAndLicenses;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(gemspecContent);

        var parsedGemspecInfo = rubyGemsUtils.ParseMetadata(gemspecContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "MIT, Ruby");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, "John Doe");
        Assert.AreEqual(parsedGemspecInfo.Name, "sampleGem");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void ParseValidGemspec_PopulatesSupplierAndSingleLicense()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var gemspecContent = SampleMetadataFiles.GemspecWithValidAuthorAndSingleLicense;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(gemspecContent);

        var parsedGemspecInfo = rubyGemsUtils.ParseMetadata(gemspecContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "MIT");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, "John Doe");
        Assert.AreEqual(parsedGemspecInfo.Name, "sampleGem");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void ParseGemspec_WithoutLicense()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var gemspecContent = SampleMetadataFiles.GemspecWithoutLicense;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(gemspecContent);

        var parsedGemspecInfo = rubyGemsUtils.ParseMetadata(gemspecContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, null);
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, "John Doe");
        Assert.AreEqual(parsedGemspecInfo.Name, "sampleGem");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void ParseGemspec_WithoutAuthor()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        var gemspecContent = SampleMetadataFiles.GemspecWithoutAuthors;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(gemspecContent);

        var parsedGemspecInfo = rubyGemsUtils.ParseMetadata(gemspecContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "MIT");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, null);
        Assert.AreEqual(parsedGemspecInfo.Name, "sampleGem");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }

    [TestMethod]
    public void GetMetdataLocation_Succeeds_Returns_Path()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns("gem_base/specifications");

        var scannedComponent = new ScannedComponent
        {
            Component = new RubyGemsComponent("testName", "1.0.0")
        };

        var gemspecLocation = rubyGemsUtils.GetMetadataLocation(scannedComponent);

        Assert.IsTrue(gemspecLocation.EndsWith("testname-1.0.0.gemspec", System.StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void GetMetdataLocation_ExecuteCommand_Fails_Returns_Null()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns((string)null);

        var scannedComponent = new ScannedComponent
        {
            Component = new RubyGemsComponent("testName", "1.0.0")
        };

        var gemspecLocation = rubyGemsUtils.GetMetadataLocation(scannedComponent);

        Assert.IsNull(gemspecLocation);
    }

    [TestMethod]
    public void GetMetdataLocation_FileDoesNotExist_Returns_Null()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(false);
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns("gem_base/specifications");

        var scannedComponent = new ScannedComponent
        {
            Component = new RubyGemsComponent("testName", "1.0.0")
        };

        var gemspecLocation = rubyGemsUtils.GetMetadataLocation(scannedComponent);

        Assert.IsNull(gemspecLocation);
    }

    [TestMethod]
    [DataRow("gem_base/specifications;gem_base/specifications2;gem_base/specifications3")]
    [DataRow("gem_base/specifications:gem_base/specifications2:gem_base/specifications3")]
    public void GetMetadataLocation_Handles_Separators(string processExecutorOutput)
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.DirectoryExists(It.IsAny<string>())).Returns(true);
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Returns(processExecutorOutput);

        var scannedComponent = new ScannedComponent
        {
            Component = new RubyGemsComponent("testName", "1.0.0")
        };

        var gemspecLocation = rubyGemsUtils.GetMetadataLocation(scannedComponent);

        Assert.IsTrue(gemspecLocation.EndsWith("testname-1.0.0.gemspec", System.StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void GetMetadataLocation_Executor_Throws()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object, mockProcessExecutor.Object);

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.DirectoryExists(It.IsAny<string>())).Returns(true);
        mockProcessExecutor.Setup(process => process.ExecuteCommand(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>())).Throws(new System.Exception());

        var scannedComponent = new ScannedComponent
        {
            Component = new RubyGemsComponent("testName", "1.0.0")
        };

        var gemspecLocation = rubyGemsUtils.GetMetadataLocation(scannedComponent);

        Assert.IsNull(gemspecLocation);
    }
}
