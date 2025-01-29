// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Convertors.Tests;

[TestClass]
public class SbomToolManifestPathConverterTests
{
    private Mock<IOSUtils> osUtils;
    private Mock<IFileSystemUtils> fileSystemUtils;
    private Mock<IFileSystemUtilsExtension> fileSystemExtensionUtils;
    private Mock<IConfiguration> configurationMock;
    private SbomToolManifestPathConverter converter;

    private bool isWindows;

    [TestInitialize]
    public void Setup()
    {
        osUtils = new Mock<IOSUtils>();
        fileSystemUtils = new Mock<IFileSystemUtils>();
        fileSystemExtensionUtils = new Mock<IFileSystemUtilsExtension>();
        configurationMock = new Mock<IConfiguration>();

        isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        converter = new SbomToolManifestPathConverter(configurationMock.Object, osUtils.Object, fileSystemUtils.Object, fileSystemExtensionUtils.Object);

        fileSystemUtils.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
            .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));
        fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
    }

    [TestMethod]
    [DataRow(nameof(OSPlatform.Windows))]
    [DataRow(nameof(OSPlatform.Linux))]
    [DataRow(nameof(OSPlatform.OSX))]
#if !NETFRAMEWORK
    [DataRow(nameof(OSPlatform.FreeBSD))]
#endif
    public void SbomToolManifestPathConverterTests_ValidPath_Succeeds(string osName)
    {
        var os = OSPlatform.Create(osName);
        var rootPath = "/Sample/Root";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);

        var (path, isOutsideDropPath) = converter.Convert(rootPath + "/hello/World");

        if (os == OSPlatform.Windows && isWindows)
        {
            rootPath = @"C:\Sample\Root";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });

            (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\World");
        }

        Assert.AreEqual("/hello/World", path);
    }

    [TestMethod]
    [DataRow(nameof(OSPlatform.Windows))]
    [DataRow(nameof(OSPlatform.Linux))]
    [DataRow(nameof(OSPlatform.OSX))]
    [DataRow(nameof(OSPlatform.FreeBSD))]
    public void SbomToolManifestPathConverterTests_ValidPathWithDot_Succeeds_LinuxBased(string osName)
    {
        var os = OSPlatform.Create(osName);
        var rootPath = "/Sample/Root/.";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);

        var (path, isOutsideDropPath) = converter.Convert(rootPath + "/hello/./World");

        if (os == OSPlatform.Windows && isWindows)
        {
            rootPath = @"C:\Sample\Root\.";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });

            (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\.\World");
        }

        Assert.AreEqual("/hello/World", path);
    }

    [TestMethod]
    [DataRow(nameof(OSPlatform.Windows))]
    [DataRow(nameof(OSPlatform.Linux))]
    [DataRow(nameof(OSPlatform.OSX))]
#if !NETFRAMEWORK
    [DataRow(nameof(OSPlatform.FreeBSD))]
#endif
    public void SbomToolManifestPathConverterTests_BuildDropPathRelative_Succeeds_LinuxBased(string osName)
    {
        var os = OSPlatform.Create(osName);
        var rootPath = "Sample/./Root/";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);

        var (path, isOutsideDropPath) = converter.Convert(rootPath + "/hello/./World");

        if (os == OSPlatform.Windows && isWindows)
        {
            rootPath = @"Sample\.\Root\";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });

            (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\.\World");
        }

        Assert.AreEqual("/hello/World", path);
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_CaseSensitive_Windows_Succeeds()
    {
        var os = OSPlatform.Windows;
        if (!isWindows)
        {
            Assert.Inconclusive("This test will only run on Windows");
        }

        var rootPath = @"C:\Sample\Root";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);

        var (path, isOutsideDropPath) = converter.Convert(@"C:\sample\Root" + @"\hello\World");
        Assert.AreEqual("/hello/World", path);
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_CaseSensitive_FreeBSD_Succeeds()
    {
        var os = OSPlatform.FreeBSD;
        if (isWindows)
        {
            Assert.Inconclusive("This test will only run on Linux");
        }

        var rootPath = @"/sample/Root";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);

        var (path, isOutsideDropPath) = converter.Convert(rootPath + @"/hello/World");
        Assert.AreEqual("/hello/World", path);
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_CaseSensitive_OSX_Fails()
    {
        var rootPath = @"C:\Sample\Root";
        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.OSX);
        fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        Assert.ThrowsException<InvalidPathException>(() => converter.Convert(@"C:\sample\Root" + @"\hello\World"));
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_CaseSensitive_Linux_Fails()
    {
        var rootPath = @"C:\Sample\Root";
        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Linux);
        fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        Assert.ThrowsException<InvalidPathException>(() => converter.Convert(@"C:\sample\Root" + @"\hello\World"));
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_RootPathOutside_Fails()
    {
        var rootPath = @"C:\Sample\Root";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
        fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        Assert.ThrowsException<InvalidPathException>(() => converter.Convert(@"d:\Root\hello\World"));
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_RootPathOutside_SbomOnDifferentDrive_Succeeds()
    {
        if (!isWindows)
        {
            Assert.Inconclusive("This test will only run on Windows");
        }

        var rootPath = @"C:\Sample\Root";
        var filePath = @"d:\Root\hello\World.spdx.json";
        var expectedPath = @"/d:/Root/hello/World.spdx.json";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
        var (path, isOutsideDropPath) = converter.Convert(filePath);
        Assert.AreEqual(expectedPath, path);
    }

    [TestMethod]
    public void SbomToolManifestPathConverterTests_RootPathOutside_SbomOnSameDrive_Succeeds()
    {
        if (!isWindows)
        {
            Assert.Inconclusive("This test will only run on Windows");
        }

        var rootPath = @"C:\Sample\Root";
        var filePath = @"C:\Sample\hello\World.spdx.json";
        var expectedPath = @"/../hello/World.spdx.json";

        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
        osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
        var (path, isOutsideDropPath) = converter.Convert(filePath);
        Assert.AreEqual(expectedPath, path);
    }
}
