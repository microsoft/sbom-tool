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
    [TestMethod]
    public void ManifestFolderFilterTest_CheckAllManifestFolder_Succeeds()
    {
        bool isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        //if os doesn't contain windows in the name then return;
        if (!isWindows)
        {
            return;
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
}