// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Sbom.Api.Filters;
using System;
using System.Collections.Generic;
using System.Text;
using Moq;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Utils;
using Serilog;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Filters.Tests
{
    [TestClass]
    public class DownloadedRootPathFilterTests
    {
        private readonly Mock<ILogger> logger = new Mock<ILogger>();

        [TestMethod]
        public void DownloadedRootPathFilterTest_NoFilterPath_Succeeds()
        {
            var fileSystemMock = new Mock<IFileSystemUtils>();

            var configMock = new Mock<IConfiguration>();
            configMock.SetupGet(c => c.RootPathFilter).Returns((ConfigurationSetting<string>)null);

            var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
            filter.Init();

            Assert.IsTrue(filter.IsValid("hello"));
            Assert.IsTrue(filter.IsValid(null));
            Assert.IsTrue(filter.IsValid("c:/test"));
            fileSystemMock.VerifyAll();
            configMock.VerifyAll();
        }

        [TestMethod]
        public void DownloadedRootPathFilterTest_FilterPath_Succeeds()
        {
            var fileSystemMock = new Mock<IFileSystemUtils>();
            fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string r, string p) => $"{r}/{p}");

            var configMock = new Mock<IConfiguration>();
            configMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "C:/test" });
            configMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "validPath" });

            var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
            filter.Init();

            Assert.IsTrue(filter.IsValid("c:/test/validPath/test"));
            Assert.IsTrue(filter.IsValid("c:/test/validPath"));
            Assert.IsTrue(filter.IsValid("c:/test/validPath/test/me"));
            Assert.IsFalse(filter.IsValid(null));
            Assert.IsFalse(filter.IsValid("c:/test/InvalidPath"));
            Assert.IsFalse(filter.IsValid("c:/test/InvalidPath/f"));

            fileSystemMock.VerifyAll();
            configMock.VerifyAll();
        }
    }
}