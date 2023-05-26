// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests.Config;

[TestClass]
public class ConfigSanitizerTests
{
    private Mock<IFileSystemUtils> mockFileSystemUtils;
    private Mock<IHashAlgorithmProvider> mockHashAlgorithmProvider;
    private Mock<IAssemblyConfig> mockAssemblyConfig;
    private ConfigSanitizer configSanitizer;
    private bool isWindows;

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

        isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

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
            },
            Verbosity = new ConfigurationSetting<Serilog.Events.LogEventLevel>
            {
                Source = SettingSource.Default,
                Value = Serilog.Events.LogEventLevel.Information
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
        config.ManifestDirPath = null;
        configSanitizer.SanitizeConfig(config);

        Assert.IsNotNull(config.ManifestDirPath);
        Assert.IsNotNull(config.ManifestDirPath.Value);

        var expectedPath = Path.Join("dropPath", "_manifest");
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));
    }

    [TestMethod]
    public void ManifestDirShouldEndWithManifestDirForGenerate_Succeeds()
    {
        var config = GetConfigurationBaseObject();
        config.ManifestDirPath = new ConfigurationSetting<string>("manifestDirPath");

        config.ManifestToolAction = ManifestToolActions.Generate;
        configSanitizer.SanitizeConfig(config);

        Assert.IsNotNull(config.ManifestDirPath);
        Assert.IsNotNull(config.ManifestDirPath.Value);

        var expectedPath = Path.Join("manifestDirPath", "_manifest");
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));
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
    }

    [TestMethod]
    public void UserProviderNamespaceUriBaseShouldReturnProvidedValue_Succeeds()
    {
        mockAssemblyConfig.SetupGet(a => a.DefaultSBOMNamespaceBaseUri).Returns("http://internal.base.uri");
        var providedNamespaceValue = "http://base.uri";
        var config = GetConfigurationBaseObject();
        config.NamespaceUriBase = new ConfigurationSetting<string>
        {
            Source = SettingSource.CommandLine,
            Value = providedNamespaceValue
        };

        config.ManifestToolAction = ManifestToolActions.Validate;
        configSanitizer.SanitizeConfig(config);

        Assert.AreEqual(providedNamespaceValue, config.NamespaceUriBase.Value);
        Assert.AreEqual(SettingSource.CommandLine, config.NamespaceUriBase.Source);

        mockAssemblyConfig.VerifyGet(a => a.DefaultSBOMNamespaceBaseUri);
    }

    [TestMethod]
    public void ShouldGetPackageSupplierFromAsseblyConfig_Succeeds()
    {
        var organization = "Contoso International";
        mockAssemblyConfig.SetupGet(a => a.DefaultPackageSupplier).Returns(organization);
        var config = GetConfigurationBaseObject();

        config.ManifestToolAction = ManifestToolActions.Validate;
        configSanitizer.SanitizeConfig(config);

        Assert.AreEqual(organization, config.PackageSupplier.Value);

        mockAssemblyConfig.VerifyGet(a => a.DefaultPackageSupplier);
    }

    [TestMethod]
    public void ShouldNotOverridePackageSupplierIfProvided_Succeeds()
    {
        var organization = "Contoso International";
        var actualOrg = "Contoso";
        mockAssemblyConfig.SetupGet(a => a.DefaultPackageSupplier).Returns(organization);
        var config = GetConfigurationBaseObject();
        config.PackageSupplier = new ConfigurationSetting<string>
        {
            Source = SettingSource.CommandLine,
            Value = actualOrg
        };

        config.ManifestToolAction = ManifestToolActions.Validate;
        configSanitizer.SanitizeConfig(config);

        Assert.AreEqual(actualOrg, config.PackageSupplier.Value);
    }

    [TestMethod]
    [DataRow(ManifestToolActions.Validate)]
    [DataRow(ManifestToolActions.Generate)]
    public void ConfigSantizer_Validate_ReplacesBackslashes_Linux(ManifestToolActions action)
    {
        if (!isWindows)
        {
            var config = GetConfigurationBaseObject();
            config.ManifestDirPath = new ($"\\{nameof(config.ManifestDirPath)}\\", SettingSource.Default);
            config.BuildDropPath = new ($"\\{nameof(config.BuildDropPath)}\\", SettingSource.Default);
            config.OutputPath = new ($"\\{nameof(config.OutputPath)}\\", SettingSource.Default);
            config.ConfigFilePath = new ($"\\{nameof(config.ConfigFilePath)}\\", SettingSource.Default);
            config.RootPathFilter = new ($"\\{nameof(config.RootPathFilter)}\\", SettingSource.Default);
            config.BuildComponentPath = new ($"\\{nameof(config.BuildComponentPath)}\\", SettingSource.Default);
            config.CatalogFilePath = new ($"\\{nameof(config.CatalogFilePath)}\\", SettingSource.Default);
            config.TelemetryFilePath = new ($"\\{nameof(config.TelemetryFilePath)}\\", SettingSource.Default);

            config.ManifestToolAction = action;
            configSanitizer.SanitizeConfig(config);

            Assert.IsTrue(config.ManifestDirPath.Value.StartsWith($"/{nameof(config.ManifestDirPath)}/"));
            Assert.IsTrue(config.BuildDropPath.Value.StartsWith($"/{nameof(config.BuildDropPath)}/"));
            Assert.IsTrue(config.OutputPath.Value.StartsWith($"/{nameof(config.OutputPath)}/"));
            Assert.IsTrue(config.ConfigFilePath.Value.StartsWith($"/{nameof(config.ConfigFilePath)}/"));
            Assert.IsTrue(config.RootPathFilter.Value.StartsWith($"/{nameof(config.RootPathFilter)}/"));
            Assert.IsTrue(config.BuildComponentPath.Value.StartsWith($"/{nameof(config.BuildComponentPath)}/"));
            Assert.IsTrue(config.CatalogFilePath.Value.StartsWith($"/{nameof(config.CatalogFilePath)}/"));
            Assert.IsTrue(config.TelemetryFilePath.Value.StartsWith($"/{nameof(config.TelemetryFilePath)}/"));
        }
    }
}