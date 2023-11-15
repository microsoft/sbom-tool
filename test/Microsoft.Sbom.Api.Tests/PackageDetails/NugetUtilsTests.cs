// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using NuGet.Configuration;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.PackageDetails;

[TestClass]
public class NugetUtilsTests
{
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();

    private static readonly string NugetPackagesPath = SettingsUtility.GetGlobalPackagesFolder(new NullSettings());

    [TestMethod]
    public void GetNuspecLocation_WhenNuspecExists_ShouldReturnPath()
    {
        var nugetUtils = new NugetUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new NuGetComponent("testName", "1.0.0")
        };

        var nuspecPath = $"{NugetPackagesPath}{((NuGetComponent)scannedComponent.Component).Name.ToLower()}/{((NuGetComponent)scannedComponent.Component).Version}/{((NuGetComponent)scannedComponent.Component).Name.ToLower()}.nuspec";

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);

        var result = nugetUtils.GetMetadataLocation(scannedComponent);

        Assert.AreEqual(nuspecPath, result);
    }

    [TestMethod]
    public void GetNuspecLocation_WhenNuspecDoesNotExist_ShouldReturnNull()
    {
        var nugetUtils = new NugetUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var scannedComponent = new ScannedComponent
        {
            Component = new NuGetComponent("testName", "1.0.0")
        };

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(false);

        var result = nugetUtils.GetMetadataLocation(scannedComponent);

        Assert.IsNull(result);
    }

    [TestMethod]
    public void ParseNuspec_WhenNuspecIsValid()
    {
        var nugetUtils = new NugetUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var nuspecContent = SampleMetadataFiles.NuspecWithValidLicenseAndAuthors;

        // Convert nuspecContent to an array of bytes
        var nuspecBytes = Encoding.UTF8.GetBytes(nuspecContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(nuspecBytes);

        var (name, version, packageDetails) = nugetUtils.ParseMetadata(nuspecContent);

        Assert.AreEqual("FakePackageName", name);
        Assert.AreEqual("1.0", version);
        Assert.AreEqual("FakeLicense", packageDetails.License);
        Assert.AreEqual("Organization: FakeAuthor", packageDetails.Supplier);
    }

    [TestMethod]
    public void ParseNuspec_LicenseIsFile_SupplierSucceeds()
    {
        var nugetUtils = new NugetUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var nuspecContent = SampleMetadataFiles.NuspecWithInvalidLicense;

        // Convert nuspecContent to an array of bytes
        var nuspecBytes = Encoding.UTF8.GetBytes(nuspecContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(nuspecBytes);

        var (name, version, packageDetails) = nugetUtils.ParseMetadata(nuspecContent);

        Assert.AreEqual("FakePackageName", name);
        Assert.AreEqual("1.0", version);
        Assert.AreEqual("Organization: FakeAuthor", packageDetails.Supplier);
        Assert.IsTrue(string.IsNullOrEmpty(packageDetails.License));
    }

    [TestMethod]
    public void ParseNuspec_NoAuthorFound_DoesNotFail()
    {
        var nugetUtils = new NugetUtils(mockFileSystemUtils.Object, mockLogger.Object, mockRecorder.Object);

        var nuspecContent = SampleMetadataFiles.NuspecWithoutAuthor;

        // Convert nuspecContent to an array of bytes
        var nuspecBytes = Encoding.UTF8.GetBytes(nuspecContent);

        mockFileSystemUtils.Setup(fs => fs.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.FileExists(It.IsAny<string>())).Returns(true);
        mockFileSystemUtils.Setup(fs => fs.ReadAllBytes(It.IsAny<string>())).Returns(nuspecBytes);

        var (name, version, packageDetails) = nugetUtils.ParseMetadata(nuspecContent);

        Assert.AreEqual("FakePackageName", name);
        Assert.AreEqual("1.0", version);
        Assert.IsTrue(string.IsNullOrEmpty(packageDetails.Supplier));
    }
}
