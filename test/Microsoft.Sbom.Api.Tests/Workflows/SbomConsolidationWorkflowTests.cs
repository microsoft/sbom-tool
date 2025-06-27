// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class SbomConsolidationWorkflowTests
{
    private const string SPDX22FilePath = "rootpath/_manifest/spdx_2.2/manifest.spdx.json";
    private const string SPDX30FilePath = "rootpath/_manifest/spdx_3.0/manifest.spdx.json";

    private Mock<ILogger> loggerMock;
    private Mock<IConfiguration> configurationMock;
    private Mock<IWorkflow<SbomGenerationWorkflow>> sbomGenerationWorkflowMock;
    private Mock<IMergeableContentProvider> mergeableContent22ProviderMock;
    private Mock<IMergeableContentProvider> mergeableContent30ProviderMock;
    private SbomConsolidationWorkflow testSubject;

    [TestInitialize]
    public void BeforeEachTest()
    {
        loggerMock = new Mock<ILogger>();  // Intentionally not using Strict to streamline setup
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomGenerationWorkflowMock = new Mock<IWorkflow<SbomGenerationWorkflow>>(MockBehavior.Strict);
        mergeableContent22ProviderMock = new Mock<IMergeableContentProvider>(MockBehavior.Strict);
        mergeableContent30ProviderMock = new Mock<IMergeableContentProvider>(MockBehavior.Strict);

        mergeableContent22ProviderMock.Setup(m => m.ManifestInfo)
            .Returns(Constants.SPDX22ManifestInfo);
        mergeableContent30ProviderMock.Setup(m => m.ManifestInfo)
            .Returns(Constants.SPDX30ManifestInfo);

        testSubject = new SbomConsolidationWorkflow(
            loggerMock.Object,
            configurationMock.Object,
            sbomGenerationWorkflowMock.Object,
            new[] { mergeableContent22ProviderMock.Object, mergeableContent30ProviderMock.Object });
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        loggerMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomGenerationWorkflowMock.VerifyAll();
        mergeableContent22ProviderMock.VerifyAll();
        mergeableContent30ProviderMock.VerifyAll();
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RunAsync_MinimalHappyPath_CallsGenerationWorkflow(bool expectedResult)
    {
        sbomGenerationWorkflowMock.Setup(x => x.RunAsync())
            .ReturnsAsync(expectedResult);
        mergeableContent22ProviderMock.Setup(x => x.TryGetContent(SPDX22FilePath, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);
        mergeableContent30ProviderMock.Setup(x => x.TryGetContent(SPDX30FilePath, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);

        testSubject.SourceSbomsTemp = new List<(ManifestInfo, string)>
        {
            (Constants.SPDX22ManifestInfo, SPDX22FilePath),
            (Constants.SPDX30ManifestInfo, SPDX30FilePath),
        };

        var result = await testSubject.RunAsync();

        Assert.AreEqual(expectedResult, result);
    }
}
