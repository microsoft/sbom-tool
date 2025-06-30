// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class SbomConsolidationWorkflowTests
{
    private const string ArtifactKey1 = "sbom-key-1";
    private const string ArtifactKey2 = "sbom-key-2";
    private const string ExternalManifestDir2 = "external-manifest-dir-2";
    private const string RelativePathToSpdx22Manifest = "/spdx_2.2/manifest.json";
    private const string RelativePathToSpdx30Manifest = "/spdx_3.0/manifest.json";
    private const string PathToSpdx22ManifestForArtifactKey1 = ArtifactKey1 + RelativePathToSpdx22Manifest;
    private const string PathToSpdx30ManifestForArtifactKey1 = ArtifactKey1 + RelativePathToSpdx30Manifest;
    private const string PathToSpdx22ManifestForArtifactKey2 = ExternalManifestDir2 + RelativePathToSpdx22Manifest;
    private const string PathToSpdx30ManifestForArtifactKey2 = ExternalManifestDir2 + RelativePathToSpdx30Manifest;

    private Mock<ILogger> loggerMock;
    private Mock<IConfiguration> configurationMock;
    private Mock<IWorkflow<SbomGenerationWorkflow>> sbomGenerationWorkflowMock;
    private Mock<IMergeableContentProvider> mergeableContent22ProviderMock;
    private Mock<IMergeableContentProvider> mergeableContent30ProviderMock;
    private Mock<ISbomConfigFactory> sbomConfigFactoryMock;
    private Mock<ISPDXFormatDetector> spdxFormatDetectorMock;
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IMetadataBuilderFactory> metadataBuilderFactoryMock;
    private SbomConsolidationWorkflow testSubject;

    private Dictionary<string, ArtifactInfo> artifactInfoMapStub = new Dictionary<string, ArtifactInfo>()
    {
        { ArtifactKey1, new ArtifactInfo() { } },
        { ArtifactKey2, new ArtifactInfo() { ExternalManifestDir = ExternalManifestDir2 } },
    };

    [TestInitialize]
    public void BeforeEachTest()
    {
        loggerMock = new Mock<ILogger>();  // Intentionally not using Strict to streamline setup
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomGenerationWorkflowMock = new Mock<IWorkflow<SbomGenerationWorkflow>>(MockBehavior.Strict);
        sbomConfigFactoryMock = new Mock<ISbomConfigFactory>(MockBehavior.Strict);
        spdxFormatDetectorMock = new Mock<ISPDXFormatDetector>(MockBehavior.Strict);
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        metadataBuilderFactoryMock = new Mock<IMetadataBuilderFactory>(MockBehavior.Strict);
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
            sbomConfigFactoryMock.Object,
            spdxFormatDetectorMock.Object,
            fileSystemUtilsMock.Object,
            metadataBuilderFactoryMock.Object,
            new[] { mergeableContent22ProviderMock.Object, mergeableContent30ProviderMock.Object });
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        loggerMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomGenerationWorkflowMock.VerifyAll();
        sbomConfigFactoryMock.VerifyAll();
        spdxFormatDetectorMock.VerifyAll();
        fileSystemUtilsMock.VerifyAll();
        metadataBuilderFactoryMock.VerifyAll();
        mergeableContent22ProviderMock.VerifyAll();
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnNoArtifactInfoMapInput()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(new Dictionary<string, ArtifactInfo>()));

        var result = await testSubject.RunAsync();
        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnNoValidSpdxSbomsFound()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(artifactInfoMapStub));

        foreach (var (key, artifactInfo) in artifactInfoMapStub)
        {
            if (artifactInfo.ExternalManifestDir == null)
            {
                fileSystemUtilsMock
                    .Setup(m => m.JoinPaths(key, Constants.ManifestFolder))
                    .Returns(key);
            }

            IList<(string, ManifestInfo)> detectedSboms;
            spdxFormatDetectorMock
                .Setup(m => m.TryGetSbomsWithVersion(artifactInfo.ExternalManifestDir ?? key, out detectedSboms))
                .Returns(false);
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
        mergeableContent22ProviderMock.Setup(x => x.TryGetContent(PathToSpdx22ManifestForArtifactKey1, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);
        mergeableContent22ProviderMock.Setup(x => x.TryGetContent(PathToSpdx22ManifestForArtifactKey2, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);
        mergeableContent30ProviderMock.Setup(x => x.TryGetContent(PathToSpdx30ManifestForArtifactKey1, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);
        mergeableContent30ProviderMock.Setup(x => x.TryGetContent(PathToSpdx30ManifestForArtifactKey2, out It.Ref<MergeableContent>.IsAny))
            .Returns(true);

        var result = await testSubject.RunAsync();
        Assert.AreEqual(expectedResult, result);
    }

    private void SetUpSbomsToValidate()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(artifactInfoMapStub));

        foreach (var (key, artifactInfo) in artifactInfoMapStub)
        {
            if (artifactInfo.ExternalManifestDir == null)
            {
                fileSystemUtilsMock
                    .Setup(m => m.JoinPaths(key, Constants.ManifestFolder))
                    .Returns(key);
            }

            var manifestDirPath = artifactInfo.ExternalManifestDir ?? key;
            IList<(string, ManifestInfo)> res = new List<(string, ManifestInfo)>()
            {
                (manifestDirPath, Constants.SPDX22ManifestInfo),
                (manifestDirPath, Constants.SPDX30ManifestInfo)
            };
            spdxFormatDetectorMock
                .Setup(m => m.TryGetSbomsWithVersion(manifestDirPath, out res))
                .Returns(true);
            sbomConfigFactoryMock
                .Setup(m => m.Get(Constants.SPDX22ManifestInfo, manifestDirPath, metadataBuilderFactoryMock.Object))
                .Returns(new SbomConfig(fileSystemUtilsMock.Object)
                {
                    ManifestInfo = Constants.SPDX22ManifestInfo,
                    ManifestJsonDirPath = manifestDirPath,
                    ManifestJsonFilePath = $"{manifestDirPath}{RelativePathToSpdx22Manifest}",
                });
            sbomConfigFactoryMock
                .Setup(m => m.Get(Constants.SPDX30ManifestInfo, manifestDirPath, metadataBuilderFactoryMock.Object))
                .Returns(new SbomConfig(fileSystemUtilsMock.Object)
                {
                    ManifestInfo = Constants.SPDX30ManifestInfo,
                    ManifestJsonDirPath = manifestDirPath,
                    ManifestJsonFilePath = $"{manifestDirPath}{RelativePathToSpdx30Manifest}",
                });
        }
    }
}
