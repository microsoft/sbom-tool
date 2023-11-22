// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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

    [TestMethod]
    public void ParseValidGemspec_PopulatesSupplierAndMultipleLicenses()
    {
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

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
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

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
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

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
        var rubyGemsUtils = new RubyGemsUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var gemspecContent = SampleMetadataFiles.GemspecWithoutAuthors;

        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllText(It.IsAny<string>())).Returns(gemspecContent);

        var parsedGemspecInfo = rubyGemsUtils.ParseMetadata(gemspecContent);

        Assert.AreEqual(parsedGemspecInfo.PackageDetails.License, "MIT");
        Assert.AreEqual(parsedGemspecInfo.PackageDetails.Supplier, null);
        Assert.AreEqual(parsedGemspecInfo.Name, "sampleGem");
        Assert.AreEqual(parsedGemspecInfo.Version, "1.0.0");
    }
}
