// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Config
{
    [TestClass]
    public class ConfigSanitizerTests
    {
        private Mock<IFileSystemUtils> mockFileSystemUtils;
        private Mock<IHashAlgorithmProvider> mockHashAlgorithmProvider;
        private Mock<IAssemblyConfig> mockAssemblyConfig;
        private ConfigSanitizer configSanitizer;

        [TestInitialize]
        public void Initialize()
        {
            mockFileSystemUtils = new Mock<IFileSystemUtils>();
            mockFileSystemUtils
                .Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string p1, string p2) => Path.Join(p1, p2));

            mockHashAlgorithmProvider = new Mock<IHashAlgorithmProvider>();
            mockHashAlgorithmProvider
                .Setup(h => h.Get(It.IsAny<string>()))
                .Returns((string a) =>
                {
                    if (a == "SHA256")
                    {
                        return new AlgorithmName(a, stream => SHA256.Create().ComputeHash(stream));
                    }

                    throw new UnsupportedHashAlgorithmException("Unsupported");
                });

            mockAssemblyConfig = new Mock<IAssemblyConfig>();

            configSanitizer = new ConfigSanitizer(mockHashAlgorithmProvider.Object, mockFileSystemUtils.Object, mockAssemblyConfig.Object);
        }

        /// <summary>
        /// This method returns a configuration object with all the properties set to standard values, 
        /// which won't make the test fail. Change one value that you are testing in order to ensure you
        /// are testing the correct config.
        /// </summary>
        /// <returns></returns>
        private Configuration GetConfigurationBaseObject()
        {
            return new Configuration
            {
                HashAlgorithm = new ConfigurationSetting<AlgorithmName>
                {
                    Source = SettingSource.CommandLine,
                    Value = new AlgorithmName("SHA256", null)
                },
                BuildDropPath = new ConfigurationSetting<string>
                {
                    Source = SettingSource.Default,
                    Value = "dropPath"
                },
                ManifestInfo = new ConfigurationSetting<IList<ManifestInfo>>
                {
                    Source = SettingSource.Default,
                    Value = new List<ManifestInfo>
                    { Constants.TestManifestInfo }
                }
            };
        }

        [TestMethod]
        public void SetValueForManifestInfoForValidation_Succeeds()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);

            mockAssemblyConfig.Verify();
        }

        [TestMethod]
        [ExpectedException(typeof(ValidationArgException))]
        public void NoValueForManifestInfoForValidation_Throws()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestToolAction = ManifestToolActions.Validate;
            config.ManifestInfo.Value.Clear();

            configSanitizer.SanitizeConfig(config);
        }

        [TestMethod]
        public void NoValueForManifestInfoForValidation_SetsDefaultValue()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestToolAction = ManifestToolActions.Validate;
            config.ManifestInfo.Value.Clear();
            mockAssemblyConfig.SetupGet(a => a.DefaultManifestInfoForValidationAction).Returns(Constants.TestManifestInfo);

            var sanitizedConfig = configSanitizer.SanitizeConfig(config);

            Assert.IsNotNull(sanitizedConfig.ManifestInfo.Value);
            Assert.AreEqual(1, sanitizedConfig.ManifestInfo.Value.Count);
            Assert.AreEqual(Constants.TestManifestInfo, sanitizedConfig.ManifestInfo.Value.First());

            mockAssemblyConfig.VerifyGet(a => a.DefaultManifestInfoForValidationAction);
        }

        [TestMethod]
        public void ForGenerateActionIgnoresEmptyAlgorithmName_Succeeds()
        {
            var config = GetConfigurationBaseObject();
            config.HashAlgorithm = null;
            config.ManifestToolAction = ManifestToolActions.Generate;
            var sanitizedConfig = configSanitizer.SanitizeConfig(config);

            Assert.IsNull(sanitizedConfig.HashAlgorithm);
        }

        [TestMethod]
        public void ForValidateGetsRealAlgorithmName_Succeeds_DoesNotThrow()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestToolAction = ManifestToolActions.Validate;
            var sanitizedConfig = configSanitizer.SanitizeConfig(config);

            Assert.IsNotNull(sanitizedConfig.HashAlgorithm);

            var result = config.HashAlgorithm.Value.ComputeHash(TestUtils.GenerateStreamFromString("Hekki"));
            Assert.IsNotNull(result);
        }

        [TestMethod]
        [ExpectedException(typeof(UnsupportedHashAlgorithmException))]
        public void ForValidateBadAlgorithmNameGetsRealAlgorithmName_Throws()
        {
            var config = GetConfigurationBaseObject();
            config.HashAlgorithm.Value = new AlgorithmName("a", null);
            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);
        }

        [TestMethod]
        public void NullManifestDirShouldUseDropPath_Succeeds()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);

            Assert.IsNotNull(config.ManifestDirPath);
            Assert.IsNotNull(config.ManifestDirPath.Value);
            Assert.AreEqual(Path.Join("dropPath", "_manifest"), config.ManifestDirPath.Value);
        }

        [TestMethod]
        public void ManifestDirShouldEndWithManifestDirForGenerate_Succeeds()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestDirPath = new ConfigurationSetting<string>
            {
                Source = SettingSource.Default,
                Value = "manifestDirPath"
            };

            config.ManifestToolAction = ManifestToolActions.Generate;
            configSanitizer.SanitizeConfig(config);

            Assert.IsNotNull(config.ManifestDirPath);
            Assert.IsNotNull(config.ManifestDirPath.Value);
            Assert.AreEqual(Path.Join("manifestDirPath", "_manifest"), config.ManifestDirPath.Value);
        }

        [TestMethod]
        public void ManifestDirShouldNotAddManifestDirForValidate_Succeeds()
        {
            var config = GetConfigurationBaseObject();
            config.ManifestDirPath = new ConfigurationSetting<string>
            {
                Source = SettingSource.Default,
                Value = "manifestDirPath"
            };

            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);

            Assert.IsNotNull(config.ManifestDirPath);
            Assert.IsNotNull(config.ManifestDirPath.Value);
            Assert.AreEqual("manifestDirPath", config.ManifestDirPath.Value);
        }

        [TestMethod]
        public void NullDefaultNamespaceUriBaseShouldReturnExistingValue_Succeeds()
        {
            mockAssemblyConfig.SetupGet(a => a.DefaultSBOMNamespaceBaseUri).Returns(string.Empty);
            var config = GetConfigurationBaseObject();
            config.NamespaceUriBase = new ConfigurationSetting<string>
            {
                Source = SettingSource.Default,
                Value = "http://base.uri"
            };

            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);

            Assert.AreEqual("http://base.uri", config.NamespaceUriBase.Value);

            mockAssemblyConfig.VerifyGet(a => a.DefaultSBOMNamespaceBaseUri);
            mockAssemblyConfig.VerifyNoOtherCalls();
        }

        [TestMethod]
        public void UserProviderNamespaceUriBaseShouldReturnDefaultValue_Succeeds()
        {
            mockAssemblyConfig.SetupGet(a => a.DefaultSBOMNamespaceBaseUri).Returns("http://internal.base.uri");
            mockAssemblyConfig.SetupGet(a => a.DefaultSBOMNamespaceBaseUriWarningMessage).Returns("test");
            var config = GetConfigurationBaseObject();
            config.NamespaceUriBase = new ConfigurationSetting<string>
            {
                Source = SettingSource.CommandLine,
                Value = "http://base.uri"
            };

            config.ManifestToolAction = ManifestToolActions.Validate;
            configSanitizer.SanitizeConfig(config);

            Assert.AreEqual("http://internal.base.uri", config.NamespaceUriBase.Value);
            Assert.AreEqual(SettingSource.Default, config.NamespaceUriBase.Source);

            mockAssemblyConfig.VerifyGet(a => a.DefaultSBOMNamespaceBaseUri);
            mockAssemblyConfig.VerifyGet(a => a.DefaultSBOMNamespaceBaseUriWarningMessage);
            mockAssemblyConfig.VerifyNoOtherCalls();
        }
    }
}
