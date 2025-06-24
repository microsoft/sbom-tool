// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Tasks;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Config.Tests;

[TestClass]
public class ConfigFileParserTests
{
    private Mock<IFileSystemUtils> mockFileSystemUtils;
    private ConfigFileParser testSubject;
    private readonly string filePathStub = "test-path";
    private readonly string contentStub = "{\"PackageSupplier\": \"TestSupplier\",\"BuildDropPath\": \"$(BuildDropPathEnvVar)\"}";
    private readonly string envVarName = "BuildDropPathEnvVar";
    private readonly string envVarValue = "TestPath";

    [TestInitialize]
    public void Initialize()
    {
        mockFileSystemUtils = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        mockFileSystemUtils
            .Setup(f => f.ReadAllTextAsync(filePathStub))
            .ReturnsAsync(() => contentStub)
            .Verifiable();

        testSubject = new ConfigFileParser(mockFileSystemUtils.Object);
    }

    [TestMethod]
    public async Task ParseFromJsonFile_ExpandsEnvVars_SucceedsAsync()
    {
        var oldEnvVarVal = Environment.GetEnvironmentVariable(envVarName);
        try
        {
            Environment.SetEnvironmentVariable(envVarName, envVarValue);

            var result = await testSubject.ParseFromJsonFile(filePathStub);
            Assert.AreEqual("TestSupplier", result.PackageSupplier);
            Assert.AreEqual(envVarValue, result.BuildDropPath);
            mockFileSystemUtils.Verify();
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, oldEnvVarVal);
        }
    }

    [TestMethod]
    public async Task ParseFromJsonFile_ExpandsEnvVars_ReturnsEmptyStringAsync()
    {
        var oldEnvVarVal = Environment.GetEnvironmentVariable(envVarName);
        try
        {
            Environment.SetEnvironmentVariable(envVarName, null);

            var result = await testSubject.ParseFromJsonFile(filePathStub);
            Assert.AreEqual("TestSupplier", result.PackageSupplier);
            Assert.AreEqual(string.Empty, result.BuildDropPath);
            mockFileSystemUtils.Verify();
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, oldEnvVarVal);
        }
    }
}
