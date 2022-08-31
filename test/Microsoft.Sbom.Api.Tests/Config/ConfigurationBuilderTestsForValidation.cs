// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;
using System.IO;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Config.Tests
{
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

            Assert.AreEqual(configuration.BuildDropPath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.ConfigFilePath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.OutputPath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.Parallelism.Source, SettingSource.Default);
            Assert.AreEqual(configuration.Parallelism.Value, Constants.DefaultParallelism);
            Assert.AreEqual(configuration.HashAlgorithm.Source, SettingSource.CommandLine);
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

            Assert.AreEqual(configuration.BuildDropPath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.ConfigFilePath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.OutputPath.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.Parallelism.Source, SettingSource.CommandLine);
            Assert.AreEqual(configuration.Verbosity.Value, Serilog.Events.LogEventLevel.Fatal);
            Assert.AreEqual(configuration.Verbosity.Source, SettingSource.CommandLine);

            fileSystemUtilsMock.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(AutoMapperMappingException))]
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

            var configuration = await cb.GetConfiguration(args);
        }

        [TestMethod]
        [ExpectedException(typeof(ValidationArgException))]
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

            var configuration = await cb.GetConfiguration(args);
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
            Assert.AreEqual(Path.Join("BuildDropPath", Constants.ManifestFolder), config.ManifestDirPath.Value);

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
}