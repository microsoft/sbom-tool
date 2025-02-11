// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Api.Config.Tests;

[TestClass]
public class ConfigurationBuilderTestsForValidation : ConfigurationBuilderTestsBase
{
    [TestInitialize]
    public void Setup()
    {
        Init();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_CombinesConfigs()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigWithManifestPath)).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.GetDirectoryName(It.IsAny<string>())).Returns("test").Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();

        var args = new ValidationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            OutputPath = "Test",
            HashAlgorithm = AlgorithmName.SHA512
        };

        var configuration = await cb.GetConfiguration(args);

        Assert.AreEqual(SettingSource.CommandLine, configuration.BuildDropPath.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.ConfigFilePath.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.OutputPath.Source);
        Assert.AreEqual(SettingSource.Default, configuration.Parallelism.Source);
        Assert.AreEqual(Common.Constants.DefaultParallelism, configuration.Parallelism.Value);
        Assert.AreEqual(SettingSource.CommandLine, configuration.HashAlgorithm.Source);
        Assert.AreEqual(configuration.HashAlgorithm.Value, AlgorithmName.SHA512);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_CombinesConfigs_DuplicateConfig_DefaultLoses()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigWithManifestPath)).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.GetDirectoryName(It.IsAny<string>())).Returns("test").Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();

        var args = new ValidationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            OutputPath = "Test",
            Parallelism = 4,
            Verbosity = Serilog.Events.LogEventLevel.Fatal
        };

        var configuration = await cb.GetConfiguration(args);

        Assert.AreEqual(SettingSource.CommandLine, configuration.BuildDropPath.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.ConfigFilePath.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.OutputPath.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.Parallelism.Source);
        Assert.AreEqual(Serilog.Events.LogEventLevel.Fatal, configuration.Verbosity.Value);
        Assert.AreEqual(SettingSource.CommandLine, configuration.Verbosity.Source);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_CombinesConfigs_DuplicateConfig_Throws()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigWithManifestPath));

        var args = new ValidationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            OutputPath = "Test",
            ManifestDirPath = "ManifestPath"
        };

        await Assert.ThrowsExceptionAsync<AutoMapperMappingException>(() => cb.GetConfiguration(args));
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_CombinesConfigs_NegativeParallism_Throws()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigWithManifestPath));

        var args = new ValidationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            OutputPath = "Test",
            Parallelism = -1
        };

        await Assert.ThrowsExceptionAsync<ValidationArgException>(() => cb.GetConfiguration(args));
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Validation_DefaultManifestDirPath_AddsManifestDir()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new ValidationArgs
        {
            OutputPath = "Test",
            BuildDropPath = "BuildDropPath"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);
        Assert.AreEqual(Path.Join("BuildDropPath", SpdxConstants.ManifestFolder), config.ManifestDirPath.Value);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Validation_UserManifestDirPath_DoesntManifestDir()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<ValidationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();

        var args = new ValidationArgs
        {
            OutputPath = "Test",
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);
        Assert.AreEqual("ManifestDirPath", config.ManifestDirPath.Value);

        fileSystemUtilsMock.VerifyAll();
    }
}
