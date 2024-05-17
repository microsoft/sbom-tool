// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

using System.Threading.Tasks;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Workflows;

#nullable enable

[TestClass]
public class SbomRedactionWorkflowTests
{
    private Mock<ILogger> mockLogger;
    private Mock<IConfiguration> configurationMock;
    private SbomRedactionWorkflow testSubject;

    [TestInitialize]
    public void Init()
    {
        mockLogger = new Mock<ILogger>();
        configurationMock = new Mock<IConfiguration>();
        testSubject = new SbomRedactionWorkflow(
            mockLogger.Object,
            configurationMock.Object);
    }

    [TestCleanup]
    public void Reset()
    {
        mockLogger.VerifyAll();
        configurationMock.VerifyAll();
    }

    [TestMethod]
    public async Task SbomParserBasedValidationWorkflowTests_ReturnsSuccessAndValidationFailures_IgnoreMissingTrue_Succeeds()
    {
        mockLogger.Setup(x => x.Information($"Running redaction for SBOM path path and SBOM dir dir. Output dir: out"));
        configurationMock.SetupGet(c => c.SbomPath).Returns(new ConfigurationSetting<string> { Value = "path" });
        configurationMock.SetupGet(c => c.SbomDir).Returns(new ConfigurationSetting<string> { Value = "dir" });
        configurationMock.SetupGet(c => c.OutputPath).Returns(new ConfigurationSetting<string> { Value = "out" });
        var result = await testSubject.RunAsync();
        Assert.IsTrue(result);
    }
}
