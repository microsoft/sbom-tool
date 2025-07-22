// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class SbomAggregationWorkflowTests
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
    private const string TempDirPath = "temp-dir";
    private const string PackageId1 = "package-id-1";
    private const string PackageId2 = "package-id-2";

    private Mock<ILogger> loggerMock;
    private Mock<IRecorder> recorderMock;
    private Mock<IConfiguration> configurationMock;
    private Mock<IWorkflow<SbomGenerationWorkflow>> sbomGenerationWorkflowMock;
    private Mock<ISbomValidationWorkflowFactory> sbomValidationWorkflowFactoryMock;
    private Mock<IWorkflow<SbomParserBasedValidationWorkflow>> sbomValidationWorkflowMock;
    private Mock<IMergeableContentProvider> mergeableContent22ProviderMock;
    private Mock<IMergeableContentProvider> mergeableContent30ProviderMock;
    private Mock<ISbomConfigFactory> sbomConfigFactoryMock;
    private Mock<ISbomConfigProvider> sbomConfigProviderMock;
    private Mock<ISPDXFormatDetector> spdxFormatDetectorMock;
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IMetadataBuilderFactory> metadataBuilderFactoryMock;
    private SbomAggregationWorkflow testSubject;

    private List<SbomPackage> actualPackageList;

    private Dictionary<string, ArtifactInfo> artifactInfoMapStub = new Dictionary<string, ArtifactInfo>()
    {
        { ArtifactKey1, new ArtifactInfo() { IgnoreMissingFiles = true, SkipSigningCheck = true } },
        { ArtifactKey2, new ArtifactInfo() { ExternalManifestDir = ExternalManifestDir2 } },
    };

    [TestInitialize]
    public void BeforeEachTest()
    {
        loggerMock = new Mock<ILogger>();      // Intentionally not using Strict to streamline setup
        recorderMock = new Mock<IRecorder>(MockBehavior.Strict);  // Intentionally not using Strict to streamline setup
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomGenerationWorkflowMock = new Mock<IWorkflow<SbomGenerationWorkflow>>(MockBehavior.Strict);
        sbomValidationWorkflowFactoryMock = new Mock<ISbomValidationWorkflowFactory>(MockBehavior.Strict);
        sbomValidationWorkflowMock = new Mock<IWorkflow<SbomParserBasedValidationWorkflow>>(MockBehavior.Strict);
        sbomConfigFactoryMock = new Mock<ISbomConfigFactory>(MockBehavior.Strict);
        sbomConfigProviderMock = new Mock<ISbomConfigProvider>(MockBehavior.Strict);
        spdxFormatDetectorMock = new Mock<ISPDXFormatDetector>(MockBehavior.Strict);
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        metadataBuilderFactoryMock = new Mock<IMetadataBuilderFactory>(MockBehavior.Strict);
        mergeableContent22ProviderMock = new Mock<IMergeableContentProvider>(MockBehavior.Strict);
        mergeableContent30ProviderMock = new Mock<IMergeableContentProvider>(MockBehavior.Strict);

        mergeableContent22ProviderMock.Setup(m => m.ManifestInfo)
            .Returns(Constants.SPDX22ManifestInfo);
        mergeableContent30ProviderMock.Setup(m => m.ManifestInfo)
            .Returns(Constants.SPDX30ManifestInfo);

        recorderMock.Setup(m => m.TraceEvent(Events.SbomAggregationWorkflow)).Returns(new TimingRecorder(Events.SbomGenerationWorkflow));

        testSubject = new SbomAggregationWorkflow(
            loggerMock.Object,
            recorderMock.Object,
            configurationMock.Object,
            sbomGenerationWorkflowMock.Object,
            sbomValidationWorkflowFactoryMock.Object,
            sbomConfigFactoryMock.Object,
            sbomConfigProviderMock.Object,
            spdxFormatDetectorMock.Object,
            fileSystemUtilsMock.Object,
            metadataBuilderFactoryMock.Object,
            new[] { mergeableContent22ProviderMock.Object, mergeableContent30ProviderMock.Object });

        actualPackageList = null;
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        loggerMock.VerifyAll();
        recorderMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomGenerationWorkflowMock.VerifyAll();
        sbomValidationWorkflowMock.VerifyAll();
        sbomValidationWorkflowFactoryMock.VerifyAll();
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
        Assert.IsNull(actualPackageList);
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
        Assert.IsNull(actualPackageList);
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnOnlySpdx30SbomsFound()
    {
        configurationMock
            .Setup(m => m.ArtifactInfoMap)
            .Returns(new ConfigurationSetting<Dictionary<string, ArtifactInfo>>(artifactInfoMapStub));

        foreach (var (key, artifactInfo) in artifactInfoMapStub)
        {
            var manifestDirPath = artifactInfo.ExternalManifestDir ?? key;
            if (artifactInfo.ExternalManifestDir == null)
            {
                fileSystemUtilsMock
                    .Setup(m => m.JoinPaths(key, Constants.ManifestFolder))
                    .Returns(key);
            }

            IList<(string, ManifestInfo)> res = new List<(string, ManifestInfo)>()
            {
                (manifestDirPath, Constants.SPDX30ManifestInfo)
            };
            spdxFormatDetectorMock
                .Setup(m => m.TryGetSbomsWithVersion(manifestDirPath, out res))
                .Returns(true);
            sbomConfigFactoryMock
                .Setup(m => m.Get(Constants.SPDX30ManifestInfo, manifestDirPath, metadataBuilderFactoryMock.Object))
                .Returns(new SbomConfig(fileSystemUtilsMock.Object)
                {
                    ManifestInfo = Constants.SPDX30ManifestInfo,
                    ManifestJsonDirPath = manifestDirPath,
                    ManifestJsonFilePath = $"{manifestDirPath}{RelativePathToSpdx30Manifest}",
                });
        }

        var result = await testSubject.RunAsync();

        Assert.IsFalse(result);
        Assert.IsNull(actualPackageList);
    }

    [TestMethod]
    public async Task RunAsync_ReturnsFalseOnFailedValidationWorkflow()
    {
        SetUpSbomsToValidate();
        SetUpMinimalValidation(false);

        var result = await testSubject.RunAsync();

        Assert.IsFalse(result);
        Assert.IsNull(actualPackageList);
    }

    [TestMethod]
    public async Task RunAsync_MixOfValidAndInvalidInputSboms()
    {
        SetUpSbomsToValidate();
        SetupMinimalValidationMocks();

        sbomValidationWorkflowFactoryMock
            .Setup(x => x.Get(It.IsAny<IConfiguration>(), It.Is<SbomConfig>(c => c.ManifestJsonDirPath.Equals(ArtifactKey1)), It.IsAny<string>()))
            .Returns(sbomValidationWorkflowMock.Object);
        sbomValidationWorkflowMock.Setup(x => x.RunAsync()).ReturnsAsync(true);

        var sbomValidationWorkflowMock1 = new Mock<IWorkflow<SbomParserBasedValidationWorkflow>>();
        sbomValidationWorkflowFactoryMock
            .Setup(x => x.Get(It.IsAny<IConfiguration>(), It.Is<SbomConfig>(c => c.ManifestJsonDirPath.Equals(ExternalManifestDir2)), It.IsAny<string>()))
            .Returns(sbomValidationWorkflowMock1.Object);
        sbomValidationWorkflowMock1.Setup(x => x.RunAsync()).ReturnsAsync(false);

        var result = await testSubject.RunAsync();

        Assert.IsFalse(result);
        Assert.IsNull(actualPackageList);
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task RunAsync_MinimalHappyPath_CallsGenerationWorkflow(bool expectedResult)
    {
        SetUpSbomsToValidate();
        SetUpMinimalValidation();
        SetupMinimalGenerationMocks(expectedResult);
        SetupMinimalMergeableContentProviderMocks();

        var result = await testSubject.RunAsync();

        Assert.AreEqual(expectedResult, result);
        ValidateActualPackageList();
    }

    private void SetupMinimalMergeableContentProviderMocks()
    {
        // mergeableContent 1 has the root package that depends on PackageId1.
        // mergeableContent 2 has the root package that depends on PackageId2, which in turn depends on PackageId1.
        var minimalMergeableContent1 = new MergeableContent(
            [
                new SbomPackage { Id = PackageId1 }
            ],
            Enumerable.Empty<SbomRelationship>());
        var minimalMergeableContent2 = new MergeableContent(
            [
                new SbomPackage { Id = PackageId1 },
                new SbomPackage { Id = PackageId2 }
            ],
            [
                new SbomRelationship
                {
                    SourceElementId = PackageId2,
                    TargetElementId = PackageId1,
                    RelationshipType = "DEPENDS_ON"
                }
            ]);

        MergeableContent nullMergeableContent = null;

        mergeableContent22ProviderMock
            .Setup(m => m.TryGetContent(PathToSpdx22ManifestForArtifactKey1, out minimalMergeableContent1))
            .Returns(true);
        mergeableContent22ProviderMock
            .Setup(m => m.TryGetContent(PathToSpdx22ManifestForArtifactKey2, out minimalMergeableContent2))
            .Returns(true);
        mergeableContent30ProviderMock
            .Setup(m => m.TryGetContent(PathToSpdx30ManifestForArtifactKey1, out nullMergeableContent))
            .Returns(false);
        mergeableContent30ProviderMock
            .Setup(m => m.TryGetContent(PathToSpdx30ManifestForArtifactKey2, out nullMergeableContent))
            .Returns(false);

        recorderMock.Setup(m => m.RecordAggregationSource(It.IsAny<string>(), 1, 0));  // minimalMergeableContent1
        recorderMock.Setup(m => m.RecordAggregationSource(It.IsAny<string>(), 2, 1));  // minimalMergeableContent2
    }

    private void ValidateActualPackageList()
    {
        Assert.IsNotNull(actualPackageList);
        Assert.AreEqual(2, actualPackageList.Count);

        // Package order is not determined, so sort it to simplify our assertions.
        actualPackageList.Sort((x, y) => string.Compare(x.Id, y.Id, StringComparison.Ordinal));

        // PackageId1 should list PackageId2 in DependOn
        Assert.AreEqual(PackageId1, actualPackageList[0].Id);
        Assert.IsNotNull(actualPackageList[0].DependOn);
        Assert.AreEqual(1, actualPackageList[0].DependOn.Count);
        Assert.AreEqual(PackageId2, actualPackageList[0].DependOn[0]);

        // PackageId2 should have a null DependOn
        Assert.AreEqual(PackageId2, actualPackageList[1].Id);
        Assert.IsNull(actualPackageList[1].DependOn);
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

    private void SetUpMinimalValidation(bool workflowResult = true)
    {
        SetupMinimalValidationMocks();

        sbomValidationWorkflowFactoryMock
            .Setup(x => x.Get(It.IsAny<IConfiguration>(), It.IsAny<SbomConfig>(), It.IsAny<string>()))
            .Returns(sbomValidationWorkflowMock.Object);
        sbomValidationWorkflowMock.Setup(x => x.RunAsync()).ReturnsAsync(workflowResult);
    }

    private void SetupMinimalValidationMocks()
    {
        // These are sorted alphabetically, not by the order in which they are invoked
        configurationMock.Setup(m => m.BuildDropPath).Returns(new ConfigurationSetting<string>());
        configurationMock.Setup(m => m.ManifestDirPath).Returns(new ConfigurationSetting<string>("original setting"));
        configurationMock.Setup(m => m.OutputPath).Returns(new ConfigurationSetting<string>());
        configurationMock.Setup(m => m.ValidateSignature).Returns(new ConfigurationSetting<bool>(true));
        configurationMock.SetupSet(m => m.BuildDropPath = It.IsAny<ConfigurationSetting<string>>());
        configurationMock.SetupSet(m => m.IgnoreMissing = It.IsAny<ConfigurationSetting<bool>>());
        configurationMock.SetupSet(m => m.ManifestDirPath = It.IsAny<ConfigurationSetting<string>>());
        configurationMock.SetupSet(m => m.OutputPath = It.IsAny<ConfigurationSetting<string>>());
        configurationMock.SetupSet(m => m.ValidateSignature = It.IsAny<ConfigurationSetting<bool>>());
        configurationMock.SetupSet(m => m.ManifestInfo = It.IsAny<ConfigurationSetting<IList<ManifestInfo>>>());

        fileSystemUtilsMock.Setup(m => m.CreateTempSubDirectory(SbomAggregationWorkflow.WorkingDirPrefix)).Returns(TempDirPath);
        fileSystemUtilsMock.Setup(m => m.JoinPaths(TempDirPath, It.IsAny<string>())).Returns(TempDirPath);
    }

    private void SetupMinimalGenerationMocks(bool expectedResult)
    {
        // These are sorted alphabetically, not by the order in which they are invoked
        configurationMock.SetupSet(m => m.BuildComponentPath = It.IsAny<ConfigurationSetting<string>>());
        configurationMock.SetupSet(m => m.BuildDropPath = It.IsAny<ConfigurationSetting<string>>());
        configurationMock.SetupSet(m => m.ManifestInfo = It.IsAny<ConfigurationSetting<IList<ManifestInfo>>>());
        configurationMock.SetupSet(m => m.PackagesList = It.IsAny<ConfigurationSetting<IEnumerable<SbomPackage>>>())
            .Callback<ConfigurationSetting<IEnumerable<SbomPackage>>>(c => actualPackageList = c.Value.ToList());

        fileSystemUtilsMock.Setup(m => m.CreateDirectory(Path.Join(TempDirPath, "aggregated-build-drop"))).Returns<DirectoryInfo>(null);

        sbomConfigProviderMock.Setup(m => m.ClearCache());

        sbomGenerationWorkflowMock.Setup(x => x.RunAsync()).ReturnsAsync(expectedResult);
    }
}
