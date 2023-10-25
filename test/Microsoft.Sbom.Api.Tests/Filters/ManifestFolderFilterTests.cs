// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Filters.Tests;

[TestClass]
public class ManifestFolderFilterTests
{
    private bool isWindows;

    [TestInitialize]
    public void Initialize()
    {
        isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    }

    [TestMethod]
    public void ManifestFolderFilterTest_CheckAllManifestFolder_Succeeds()
    {
        // If OS is not windows then don't run the windows test.
        if (!isWindows)
        {
            Assert.Inconclusive("Test is only valid on Windows.");
        }

        var mockOSUtils = new Mock<IOSUtils>();
        mockOSUtils.Setup(o => o.GetFileSystemStringComparisonType()).Returns(StringComparison.CurrentCultureIgnoreCase);

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = "C:/test/_manifest" });

        var filter = new ManifestFolderFilter(configMock.Object, mockOSUtils.Object);
        filter.Init();

        Assert.IsTrue(filter.IsValid("c:/test"));
        Assert.IsFalse(filter.IsValid(null));
        Assert.IsTrue(filter.IsValid("c:/test/me"));
        Assert.IsTrue(filter.IsValid("me"));
        Assert.IsTrue(filter.IsValid("d:/me"));
        Assert.IsTrue(filter.IsValid("c:/test\\me"));
        Assert.IsTrue(filter.IsValid("c:\\test/me"));
        Assert.IsFalse(filter.IsValid("c:/test/_manifest"));
        Assert.IsFalse(filter.IsValid("c:/test/_manifest/manifest.json"));
        Assert.IsFalse(filter.IsValid("c:\\test\\_manifest"));
        Assert.IsFalse(filter.IsValid("c:/test/_manifest\\manifest.json"));
        configMock.VerifyAll();
    }

    [TestMethod]
    public void ManifestFolderFilterTest_CheckAllManifestFolder_Succeeds_LinuxBased()
    {
        // if OS is windows then don't run the linux test
        if (isWindows)
        {
            Assert.Inconclusive("Test is only valid on Linux.");
        }

        var mockOSUtils = new Mock<IOSUtils>();
        mockOSUtils.Setup(o => o.GetFileSystemStringComparisonType()).Returns(StringComparison.CurrentCultureIgnoreCase);

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = "home/test/_manifest" });

        var filter = new ManifestFolderFilter(configMock.Object, mockOSUtils.Object);
        filter.Init();

        Assert.IsTrue(filter.IsValid("home/test"));
        Assert.IsFalse(filter.IsValid(null));
        Assert.IsTrue(filter.IsValid("home/test/me"));
        Assert.IsTrue(filter.IsValid("me"));
        Assert.IsTrue(filter.IsValid("home/me"));
        Assert.IsTrue(filter.IsValid("home/test\\me"));
        Assert.IsTrue(filter.IsValid("home\\test/me"));
        Assert.IsFalse(filter.IsValid("home/test/_manifest"));
        Assert.IsFalse(filter.IsValid("home/test/_manifest/manifest.json"));
        Assert.IsFalse(filter.IsValid("home/test/_manifest\\manifest.json"));
        configMock.VerifyAll();
    }
}
