// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.PackageDetails;

[TestClass]
public class MavenUtilsTests
{
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILogger<MavenUtils>> mockLogger = new Mock<ILogger<MavenUtils>>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();

    private static readonly string EnvHomePath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "HOMEPATH" : "HOME";
    private static readonly string HomePath = Environment.GetEnvironmentVariable(EnvHomePath);
    private static readonly string MavenPackagesPath = Path.Join(HomePath, ".m2/repository");

    [TestMethod]
    public void GetPomLocation_WhenPomExists_ShouldReturnPath()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new MavenComponent("testGroupId", "testArtifactId", "1.0.0")
        };

        var pathToPom = Path.Join(MavenPackagesPath, "testgroupid/testartifactid/1.0.0/testartifactid-1.0.0.pom");

        var expectedPath = Path.GetFullPath(pathToPom);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = mavenUtils.GetMetadataLocation(scannedComponent);

        Assert.AreEqual(expectedPath, result);
    }

    [TestMethod]
    public void GetPomLocation_WhenPomDoesNotExist_ShouldReturnNull()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new MavenComponent("testGroupId", "testArtifactId", "1.0.0")
        };

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(false);

        var result = mavenUtils.GetMetadataLocation(scannedComponent);

        Assert.IsNull(result);
    }

    [TestMethod]
    public void ParsePom_WhenPomIsValid()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var pomContent = SampleMetadataFiles.PomWithLicensesAndDevelopers;

        // Convert pomContent to an array of bytes
        var pomBytes = Encoding.UTF8.GetBytes(pomContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(pomBytes);

        var parsedInfo = mavenUtils.ParseMetadata(pomContent);

        Assert.AreEqual("test-package", parsedInfo.Name);
        Assert.AreEqual("1.3", parsedInfo.Version);
        Assert.AreEqual("New BSD License", parsedInfo.PackageDetails.License);
        Assert.AreEqual("Person: Sample Name", parsedInfo.PackageDetails.Supplier);
    }

    [TestMethod]
    public void ParsePom_WithoutDeveloperSection()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var pomContent = SampleMetadataFiles.PomWithoutDevelopersSection;

        // Convert pomContent to an array of bytes
        var pomBytes = Encoding.UTF8.GetBytes(pomContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(pomBytes);

        var parsedInfo = mavenUtils.ParseMetadata(pomContent);

        Assert.AreEqual("test-package", parsedInfo.Name);
        Assert.AreEqual("1.3", parsedInfo.Version);
        Assert.AreEqual("New BSD License", parsedInfo.PackageDetails.License);
        Assert.IsTrue(string.IsNullOrEmpty(parsedInfo.PackageDetails.Supplier));
    }

    [TestMethod]
    public void ParsePom_WithoutLicense()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var pomContent = SampleMetadataFiles.PomWithoutLicense;

        // Convert pomContent to an array of bytes
        var pomBytes = Encoding.UTF8.GetBytes(pomContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(pomBytes);

        var parsedInfo = mavenUtils.ParseMetadata(pomContent);

        Assert.AreEqual("test-package", parsedInfo.Name);
        Assert.AreEqual("1.3", parsedInfo.Version);
        Assert.IsTrue(string.IsNullOrEmpty(parsedInfo.PackageDetails.License));
        Assert.AreEqual("Person: Sample Name", parsedInfo.PackageDetails.Supplier);
    }

    [TestMethod]
    public void ParsePom_WithOrganizationAndDevelopers_PopulatesAsOrganization()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var pomContent = SampleMetadataFiles.PomWithDevelopersAndOrganization;

        // Convert pomContent to an array of bytes
        var pomBytes = Encoding.UTF8.GetBytes(pomContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(pomBytes);

        var parsedInfo = mavenUtils.ParseMetadata(pomContent);

        Assert.AreEqual("test-package", parsedInfo.Name);
        Assert.AreEqual("1.3", parsedInfo.Version);
        Assert.IsTrue(string.IsNullOrEmpty(parsedInfo.PackageDetails.License));
        Assert.AreEqual("Organization: Microsoft", parsedInfo.PackageDetails.Supplier);
    }
}
