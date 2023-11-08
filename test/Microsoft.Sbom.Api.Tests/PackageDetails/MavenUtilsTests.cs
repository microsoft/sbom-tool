// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;
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
public class MavenUtilsTests
{
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();

    private static readonly string EnvHomePath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "HOMEPATH" : "HOME";
    private static readonly string HomePath = Environment.GetEnvironmentVariable(EnvHomePath);
    private static readonly string MavenPackagesPath = $"{HomePath}/.m2/repository";

    [TestMethod]
    public void GetPomLocation_WhenNuspecExists_ShouldReturnPath()
    {
        var mavenUtils = new MavenUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new MavenComponent("testGroupId", "testArtifactId", "1.0.0")
        };

        var expectedPomLocation = $"{MavenPackagesPath}/testgroupid/testartifactid/1.0.0/testartifactid-1.0.0.pom";

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = mavenUtils.GetPomLocation(scannedComponent);

        Assert.AreEqual(expectedPomLocation, result);
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

        var result = mavenUtils.GetPomLocation(scannedComponent);

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

        var (name, version, packageDetails) = mavenUtils.ParsePom(pomContent);

        Assert.AreEqual("test-package", name);
        Assert.AreEqual("1.3", version);
        Assert.AreEqual("New BSD License", packageDetails.License);
        Assert.AreEqual("Sample Name", packageDetails.Supplier);
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

        var (name, version, packageDetails) = mavenUtils.ParsePom(pomContent);

        Assert.AreEqual("test-package", name);
        Assert.AreEqual("1.3", version);
        Assert.AreEqual("New BSD License", packageDetails.License);
        Assert.IsTrue(string.IsNullOrEmpty(packageDetails.Supplier));
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

        var (name, version, packageDetails) = mavenUtils.ParsePom(pomContent);

        Assert.AreEqual("test-package", name);
        Assert.AreEqual("1.3", version);
        Assert.IsTrue(string.IsNullOrEmpty(packageDetails.License));
        Assert.AreEqual("Sample Name", packageDetails.Supplier);
    }
}
