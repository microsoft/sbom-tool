// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Convertors.Tests
{
    [TestClass]
    public class DropValidatorManifestPathConverterTests
    {
        private Mock<IOSUtils> osUtils;
        private Mock<IFileSystemUtils> fileSystemUtils;
        private Mock<IFileSystemUtilsExtension> fileSystemExtensionUtils;
        private Mock<IConfiguration> configurationMock;
        private DropValidatorManifestPathConverter converter;

        [TestInitialize]
        public void Setup()
        {
            osUtils = new Mock<IOSUtils>();
            fileSystemUtils = new Mock<IFileSystemUtils>();
            fileSystemExtensionUtils = new Mock<IFileSystemUtilsExtension>();
            configurationMock = new Mock<IConfiguration>();

            converter = new DropValidatorManifestPathConverter(configurationMock.Object, osUtils.Object, fileSystemUtils.Object, fileSystemExtensionUtils.Object);

            fileSystemUtils.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));
            fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_ValidPath_Succeeds()
        {
            var rootPath = @"C:\Sample\Root";
            var operatingSystems = new List<OSPlatform>() {
                OSPlatform.Windows,
                OSPlatform.Linux,
                OSPlatform.OSX,
#if !NETFRAMEWORK
                OSPlatform.FreeBSD 
#endif
                };

            foreach (var os in operatingSystems)
            {
                configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
                osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);
                var (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\World");
                Assert.AreEqual("/hello/World", path);
            }
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_ValidPathWithDot_Succeeds()
        {
            var rootPath = @"C:\Sample\Root\.";
            var operatingSystems = new List<OSPlatform>() {
                OSPlatform.Windows,
                OSPlatform.Linux,
                OSPlatform.OSX,
                OSPlatform.FreeBSD
                };

            foreach (var os in operatingSystems)
            {
                configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
                osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);
                var (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\.\World");
                Assert.AreEqual("/hello/World", path);
            }
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_BuildDropPathRelative_Succeeds()
        {
            var rootPath = @"Sample\.\Root\";
            var operatingSystems = new List<OSPlatform>() {
                OSPlatform.Windows,
                OSPlatform.Linux,
                OSPlatform.OSX,
                OSPlatform.FreeBSD
                };

            foreach (var os in operatingSystems)
            {
                configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
                osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);
                var (path, isOutsideDropPath) = converter.Convert(rootPath + @"\hello\.\World");
                Assert.AreEqual("/hello/World", path);
            }
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_CaseSensitive_Windows_FreeBSD_Succeeds()
        {
            var rootPath = @"C:\Sample\Root";
            var operatingSystems = new List<OSPlatform>() {
                OSPlatform.Windows, 
#if !NETFRAMEWORK
                OSPlatform.FreeBSD 
#endif
            };

            foreach (var os in operatingSystems)
            {
                configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
                osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(os);
                var (path, isOutsideDropPath) = converter.Convert(@"C:\sample\Root" + @"\hello\World");
                Assert.AreEqual("/hello/World", path);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidPathException))]
        public void DropValidatorManifestPathConverterTests_CaseSensitive_OSX_Fails()
        {
            var rootPath = @"C:\Sample\Root";
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
            osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.OSX);
            fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);
            var (path, isOutsideDropPath) = converter.Convert(@"C:\sample\Root" + @"\hello\World");
            Assert.AreEqual("/hello/World", path);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidPathException))]
        public void DropValidatorManifestPathConverterTests_CaseSensitive_Linux_Fails()
        {
            var rootPath = @"C:\Sample\Root";
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
            osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Linux);
            fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);
            var (path, isOutsideDropPath) = converter.Convert(@"C:\sample\Root" + @"\hello\World");
            Assert.AreEqual("/hello/World", path);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidPathException))]
        public void DropValidatorManifestPathConverterTests_RootPathOutside_Fails()
        {
            var rootPath = @"C:\Sample\Root";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
            osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
            fileSystemExtensionUtils.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

            converter.Convert(@"d:\Root\hello\World");
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_RootPathOutside_SbomOnDifferentDrive_Succeeds()
        {
            var rootPath = @"C:\Sample\Root";
            var filePath = @"d:\Root\hello\World.spdx.json";
            var expectedPath = @"/d:/Root/hello/World.spdx.json";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
            osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
            var (path, isOutsideDropPath) = converter.Convert(filePath);
            Assert.AreEqual(expectedPath, path);
        }

        [TestMethod]
        public void DropValidatorManifestPathConverterTests_RootPathOutside_SbomOnSameDrive_Succeeds()
        {
            var rootPath = @"C:\Sample\Root";
            var filePath = @"C:\Sample\hello\World.spdx.json";
            var expectedPath = @"/../hello/World.spdx.json";

            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = rootPath });
            osUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);
            var (path, isOutsideDropPath) = converter.Convert(filePath);
            Assert.AreEqual(expectedPath, path);
        }
    }
}
