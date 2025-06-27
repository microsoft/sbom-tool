// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class SbomConsolidationWorkflowTests
{
    private Mock<ILogger> loggerMock;
    private Mock<IConfiguration> configurationMock;
    private Mock<IWorkflow<SbomGenerationWorkflow>> sbomGenerationWorkflowMock;
    private SbomConsolidationWorkflow testSubject;

    [TestInitialize]
    public void BeforeEachTest()
    {
        loggerMock = new Mock<ILogger>();  // Intentionally not using Strict to streamline setup
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomGenerationWorkflowMock = new Mock<IWorkflow<SbomGenerationWorkflow>>(MockBehavior.Strict);

        testSubject = new SbomConsolidationWorkflow(
            loggerMock.Object,
            configurationMock.Object,
            sbomGenerationWorkflowMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        loggerMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomGenerationWorkflowMock.VerifyAll();
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RunAsync_MinimalHappyPath_CallsGenerationWorkflow(bool expectedResult)
    {
        sbomGenerationWorkflowMock.Setup(x => x.RunAsync())
            .ReturnsAsync(expectedResult);

        var result = await testSubject.RunAsync();

        Assert.AreEqual(expectedResult, result);
    }
}
