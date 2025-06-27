// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
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
    private Mock<ISbomConfigFactory> sbomConfigFactoryMock;
    private Mock<ISPDXFormatDetector> sPDXFormatDetectorMock;
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IMetadataBuilderFactory> metadataBuilderFactoryMock;
    private SbomConsolidationWorkflow testSubject;

    private Dictionary<string, ArtifactInfo> artifactInfoMapStub = new Dictionary<string, ArtifactInfo>()
    {
        { "sbom-key-1", new ArtifactInfo() { } },
        { "sbom-key-2", new ArtifactInfo() { ExternalManifestDir = "external-manifest-dir-2" } },
    };

    [TestInitialize]
    public void BeforeEachTest()
    {
        loggerMock = new Mock<ILogger>();  // Intentionally not using Strict to streamline setup
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomGenerationWorkflowMock = new Mock<IWorkflow<SbomGenerationWorkflow>>(MockBehavior.Strict);
        sbomConfigFactoryMock = new Mock<ISbomConfigFactory>(MockBehavior.Strict);
        sPDXFormatDetectorMock = new Mock<ISPDXFormatDetector>(MockBehavior.Strict);
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        metadataBuilderFactoryMock = new Mock<IMetadataBuilderFactory>(MockBehavior.Strict);

        testSubject = new SbomConsolidationWorkflow(
            loggerMock.Object,
            configurationMock.Object,
            sbomGenerationWorkflowMock.Object,
            sbomConfigFactoryMock.Object,
            sPDXFormatDetectorMock.Object,
            fileSystemUtilsMock.Object,
            metadataBuilderFactoryMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        loggerMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomGenerationWorkflowMock.VerifyAll();
        sbomConfigFactoryMock.VerifyAll();
        sPDXFormatDetectorMock.VerifyAll();
        fileSystemUtilsMock.VerifyAll();
        metadataBuilderFactoryMock.VerifyAll();
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnNoArtifactInfoMapInput()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(new Dictionary<string, ArtifactInfo>()))
            .Verifiable();

        var result = await testSubject.RunAsync();
        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnNoValidSpdxSbomsFound()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(artifactInfoMapStub))
            .Verifiable();
        foreach (var (key, artifactInfo) in artifactInfoMapStub)
        {
            if (artifactInfo.ExternalManifestDir == null)
            {
                fileSystemUtilsMock
                    .Setup(m => m.JoinPaths(key, Api.Utils.Constants.ManifestFolder))
                    .Returns(key)
                    .Verifiable();
            }

            IList<(string, ManifestInfo)> detectedSboms;
            sPDXFormatDetectorMock
                .Setup(m => m.TryGetSbomsWithVersion(artifactInfo.ExternalManifestDir ?? key, out detectedSboms))
                .Returns(false)
                .Verifiable();
        }

        var result = await testSubject.RunAsync();
        Assert.IsFalse(result);
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RunAsync_MinimalHappyPath_CallsGenerationWorkflow(bool expectedResult)
    {
        SetUpSbomsToValidate();

        sbomGenerationWorkflowMock.Setup(x => x.RunAsync())
            .ReturnsAsync(expectedResult);

        var result = await testSubject.RunAsync();

        Assert.AreEqual(expectedResult, result);
    }

    private void SetUpSbomsToValidate()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(artifactInfoMapStub))
            .Verifiable();
        foreach (var (key, artifactInfo) in artifactInfoMapStub)
        {
            if (artifactInfo.ExternalManifestDir == null)
            {
                fileSystemUtilsMock
                    .Setup(m => m.JoinPaths(key, Api.Utils.Constants.ManifestFolder))
                    .Returns(key)
                    .Verifiable();
            }

            var manifestDirPath = artifactInfo.ExternalManifestDir ?? key;
            IList<(string, ManifestInfo)> res = new List<(string, ManifestInfo)>()
            {
                (manifestDirPath, Api.Utils.Constants.SPDX22ManifestInfo),
                (manifestDirPath, Api.Utils.Constants.SPDX30ManifestInfo)
            };
            sPDXFormatDetectorMock
                .Setup(m => m.TryGetSbomsWithVersion(manifestDirPath, out res))
                .Returns(true)
                .Verifiable();
            sbomConfigFactoryMock
                .Setup(m => m.Get(Api.Utils.Constants.SPDX22ManifestInfo, manifestDirPath, metadataBuilderFactoryMock.Object))
                .Returns(new SbomConfig(fileSystemUtilsMock.Object) { ManifestInfo = Api.Utils.Constants.SPDX22ManifestInfo, ManifestJsonDirPath = manifestDirPath })
                .Verifiable();
            sbomConfigFactoryMock
                .Setup(m => m.Get(Api.Utils.Constants.SPDX30ManifestInfo, manifestDirPath, metadataBuilderFactoryMock.Object))
                .Returns(new SbomConfig(fileSystemUtilsMock.Object) { ManifestInfo = Api.Utils.Constants.SPDX30ManifestInfo, ManifestJsonDirPath = manifestDirPath })
                .Verifiable();
        }
    }
}
