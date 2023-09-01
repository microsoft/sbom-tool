﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Tests;

[TestClass]
public class ConfigurationBuilderTestsForGeneration : ConfigurationBuilderTestsBase
{
    [TestInitialize]
    public void Setup()
    {
        Init();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_ForGenerator_CombinesConfigs()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigGoodWithManifestInfo));
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns(Path.Join(It.IsAny<string>(), It.IsAny<string>())).Verifiable();

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var configuration = await cb.GetConfiguration(args);

        Assert.AreEqual(configuration.BuildDropPath.Source, SettingSource.CommandLine);
        Assert.AreEqual(configuration.ConfigFilePath.Source, SettingSource.CommandLine);
        Assert.AreEqual(configuration.ManifestInfo.Source, SettingSource.JsonConfig);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_ForGenerator_CombinesConfigs_CmdLineSucceeds()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString(JSONConfigGoodWithManifestInfo));
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns(Path.Join(It.IsAny<string>(), It.IsAny<string>())).Verifiable();

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ConfigFilePath = "config.json",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var configuration = await cb.GetConfiguration(args);

        Assert.AreEqual(configuration.BuildDropPath.Source, SettingSource.CommandLine);
        Assert.AreEqual(configuration.ConfigFilePath.Source, SettingSource.CommandLine);
        Assert.AreEqual(configuration.ManifestInfo.Source, SettingSource.JsonConfig);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    [ExpectedException(typeof(ValidationArgException))]
    public async Task ConfigurationBuilderTest_Generation_BuildDropPathDoNotExist_Throws()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(false);

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var configuration = await cb.GetConfiguration(args);
    }

    [TestMethod]
    [ExpectedException(typeof(AccessDeniedValidationArgException))]
    public async Task ConfigurationBuilderTest_Generation_BuildDropPathNotWriteAccess_Throws()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(false);

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var configuration = await cb.GetConfiguration(args);
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Generation_DefaultManifestDirPath_AddsManifestDir()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);

        var expectedPath = Path.Join(args.BuildDropPath, Constants.ManifestFolder);
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Generation_UserManifestDirPath_AddsManifestDir()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);

        var expectedPath = Path.Join("ManifestDirPath", Constants.ManifestFolder);
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Generation_NSBaseUri_Validated()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath",
            NamespaceUriBase = "https://base.uri",
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);

        var expectedPath = Path.Join("ManifestDirPath", Constants.ManifestFolder);
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Generation_BadNSBaseUriWithDefaultValue_Succeds()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        mockAssemblyConfig.SetupGet(a => a.DefaultSBOMNamespaceBaseUri).Returns("https://uri");

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath",
            NamespaceUriBase = "baduri",
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(config.ManifestDirPath);

        var expectedPath = Path.Join("ManifestDirPath", Constants.ManifestFolder);
        Assert.AreEqual(Path.GetFullPath(expectedPath), Path.GetFullPath(config.ManifestDirPath.Value));

        fileSystemUtilsMock.VerifyAll();
        mockAssemblyConfig.VerifyGet(a => a.DefaultSBOMNamespaceBaseUri);
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Generation_NullNSBaseUriChangesToDefault()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath",
            NamespaceUriBase = null,
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);

        Assert.IsNotNull(config);
        Assert.IsNotNull(args.ManifestDirPath);
        Assert.IsNotNull(config.NamespaceUriBase);
        Assert.AreEqual(Path.Join("ManifestDirPath", Constants.ManifestFolder), config.ManifestDirPath.Value);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    [DataRow("baduri")]
    [DataRow("https://")]
    [DataRow("ww.com")]
    [DataRow("https//test.com")]
    [ExpectedException(typeof(ValidationArgException), "The value of NamespaceUriBase must be a valid URI.")]
    public async Task ConfigurationBuilderTest_Generation_BadNSBaseUri_Fails(string badNsUri)
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<GenerationArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

        var args = new GenerationArgs
        {
            BuildDropPath = "BuildDropPath",
            ManifestDirPath = "ManifestDirPath",
            NamespaceUriBase = badNsUri,
            PackageSupplier = "Contoso"
        };

        var config = await cb.GetConfiguration(args);
    }
}
