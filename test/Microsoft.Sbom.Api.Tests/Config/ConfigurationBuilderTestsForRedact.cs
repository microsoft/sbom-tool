// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Tests;

[TestClass]
public class ConfigurationBuilderTestsForRedact : ConfigurationBuilderTestsBase
{
    [TestInitialize]
    public void Setup()
    {
        Init();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_ForRedact_CombinesConfigs()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<RedactArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns(Path.Join(It.IsAny<string>(), It.IsAny<string>())).Verifiable();

        var args = new RedactArgs
        {
            SbomDir = "SbomDir",
            OutputPath = "OutputPath"
        };

        var configuration = await cb.GetConfiguration(args);

        Assert.AreEqual(SettingSource.CommandLine, configuration.SbomDir.Source);
        Assert.AreEqual(SettingSource.CommandLine, configuration.OutputPath.Source);

        fileSystemUtilsMock.VerifyAll();
    }

    [TestMethod]
    public async Task ConfigurationBuilderTest_Redact_OuputPathNotWriteAccess_Throws()
    {
        var configFileParser = new ConfigFileParser(fileSystemUtilsMock.Object);
        var cb = new ConfigurationBuilder<RedactArgs>(mapper, configFileParser);

        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true);
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(false);

        var args = new RedactArgs
        {
            SbomDir = "SbomDir",
            OutputPath = "OutputPath"
        };

        await Assert.ThrowsExceptionAsync<ValidationArgException>(() => cb.GetConfiguration(args));
    }
}
