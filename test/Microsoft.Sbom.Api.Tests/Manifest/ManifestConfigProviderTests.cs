// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Ninject.Activation;
using PowerArgs;
using System.Collections.Generic;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Manifest.Tests
{
    [TestClass]
    public class ManifestConfigProviderTests
    {
        private readonly IMetadataBuilderFactory mockMetadataBuilderFactory;
        public ManifestConfigProviderTests()
        {
            var mockBuilderFactory = new Mock<IMetadataBuilderFactory>();
            mockMetadataBuilderFactory = mockBuilderFactory.Object;
        }

        private Mock<IFileSystemUtils> mockFileSystemUtils;

        [TestInitialize]
        public void Setup()
        {
            mockFileSystemUtils = new Mock<IFileSystemUtils>();

            mockFileSystemUtils.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            mockFileSystemUtils.Setup(m => m.JoinPaths(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string p1, string p2) => PathUtils.Join(p1, p2));

            mockFileSystemUtils.Setup(m => m.JoinPaths(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string p1, string p2, string p3) => PathUtils.Join(p1, p2, p3));
        }

        [TestMethod]
        public void ManifestConfigProviderTest_Generate_SPDX22_Succeeds()
        {
            var mockConfiguration = new Mock<IConfiguration>();
            var mockContext = new Mock<IContext>();

            mockConfiguration.Setup(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            mockConfiguration.Setup(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            mockConfiguration.Setup(c => c.ManifestToolAction).Returns(ManifestToolActions.Generate);
            mockConfiguration
                .Setup(c => c.ManifestInfo)
                .Returns(
                    new ConfigurationSetting<IList<ManifestInfo>>
                    {
                        Value = new List<ManifestInfo> { Constants.SPDX22ManifestInfo }
                    });

            var configHandlerArray = new IManifestConfigHandler[]
            {
                new SPDX22ManifestConfigHandler(mockConfiguration.Object, mockFileSystemUtils.Object, mockMetadataBuilderFactory),
            };

            var configProvider = new ManifestConfigProvider(configHandlerArray);

            var config = configProvider.Create(mockContext.Object) as SbomConfig;

            Assert.IsNotNull(config);
            Assert.IsTrue(config.ManifestInfo == Constants.SPDX22ManifestInfo);

            string sbomDirPath = PathUtils.Join("/root",
                                      Constants.ManifestFolder,
                                      $"{Constants.SPDX22ManifestInfo.Name.ToLower()}_{Constants.SPDX22ManifestInfo.Version.ToLower()}");

            // sbom file path is manifest.spdx.json in the sbom directory.
            string sbomFilePath = PathUtils.Join(sbomDirPath, $"manifest.{Constants.SPDX22ManifestInfo.Name.ToLower()}.json");
            Assert.AreEqual(config.ManifestJsonDirPath, sbomDirPath);
            Assert.AreEqual(config.ManifestJsonFilePath, sbomFilePath);
            Mock.VerifyAll();
        }

        // This test should change as the values are not non deterministic.
        [ExpectedException(typeof(ValidationArgException))]
        public void ManifestConfigProviderTest_Generate_SPDX22_Fails()
        {
            var mockConfiguration = new Mock<IConfiguration>();
            var mockContext = new Mock<IContext>();

            mockConfiguration.Setup(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            mockConfiguration.Setup(c => c.ManifestToolAction).Returns(ManifestToolActions.Generate);
            mockConfiguration
                            .Setup(c => c.ManifestInfo)
                            .Returns(
                                new ConfigurationSetting<IList<ManifestInfo>>
                                {
                                    Value = new List<ManifestInfo> { Constants.SPDX22ManifestInfo }
                                });
            var configHandlerArray = new IManifestConfigHandler[]
            {
            };

            var configProvider = new ManifestConfigProvider(configHandlerArray);

            var config = configProvider.Create(mockContext.Object) as SbomConfig;

            Assert.IsNotNull(config);
            Assert.IsTrue(config.ManifestInfo == Constants.SPDX22ManifestInfo);

            var sbomDirPath = PathUtils.Join("/root",
                                      Constants.ManifestFolder,
                                      $"{Constants.SPDX22ManifestInfo.Name.ToLower()}_{Constants.SPDX22ManifestInfo.Version.ToLower()}");

            // sbom file path is manifest.spdx.json in the sbom directory.
            var sbomFilePath = PathUtils.Join(sbomDirPath, $"manifest.{Constants.SPDX22ManifestInfo.Name.ToLower()}.json");
            Assert.IsTrue(config.ManifestJsonDirPath == sbomDirPath);
            Assert.IsTrue(config.ManifestJsonFilePath == sbomFilePath);
            Mock.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(ValidationArgException))]
        public void ManifestConfigProviderTest_Validate_SPDX_Fails()
        {
            var mockConfiguration = new Mock<IConfiguration>();
            var mockContext = new Mock<IContext>();

            mockFileSystemUtils
               .Setup(f => f.FileExists(
                   It.Is<string>(d => d.Replace("\\", "/") == "/root/_manifest/spdx_2.2/manifest.spdx.json")))
               .Returns(true);

            mockConfiguration.Setup(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            mockConfiguration.Setup(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            mockConfiguration.Setup(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);

            var configHandlerArray = new IManifestConfigHandler[]
            {
                new SPDX22ManifestConfigHandler(mockConfiguration.Object, mockFileSystemUtils.Object, mockMetadataBuilderFactory)
            };

            var configProvider = new ManifestConfigProvider(configHandlerArray);

            configProvider.Create(mockContext.Object);
        }
    }
}