// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.Executors;

[TestClass]
public class PackageInfoJsonWriterTests
{
    private const string TestEntityId = "TestEntityId";

    private Mock<IManifestGenerator> manifestGeneratorMock;
    private Mock<IManifestGeneratorProvider> manifestGeneratorProviderMock;
    private Mock<ILogger> loggerMock;
    private Mock<ISbomConfig> sbomConfigMock;
    private Mock<ISbomPackageDetailsRecorder> sbomPackageDetailsRecorderMock;
    private Mock<IManifestToolJsonSerializer> manifestToolJsonSerializerMock;
    private PackageInfoJsonWriter testSubject;
    private GenerationResult generationResult;

    [TestInitialize]
    public void BeforeEach()
    {
        manifestGeneratorMock = new Mock<IManifestGenerator>();
        manifestGeneratorProviderMock = new Mock<IManifestGeneratorProvider>();
        loggerMock = new Mock<ILogger>();
        sbomPackageDetailsRecorderMock = new Mock<ISbomPackageDetailsRecorder>(MockBehavior.Strict);
        manifestToolJsonSerializerMock = new Mock<IManifestToolJsonSerializer>();
        testSubject = new PackageInfoJsonWriter(manifestGeneratorProviderMock.Object, loggerMock.Object);

        sbomConfigMock = new Mock<ISbomConfig>(MockBehavior.Strict);
        sbomConfigMock.SetupGet(x => x.ManifestInfo).Returns(Constants.TestManifestInfo);
        sbomConfigMock.SetupGet(x => x.Recorder).Returns(sbomPackageDetailsRecorderMock.Object);
        sbomConfigMock.SetupGet(x => x.JsonSerializer).Returns(manifestToolJsonSerializerMock.Object);

        generationResult = new GenerationResult
        {
            ResultMetadata = new ResultMetadata
            {
                EntityId = TestEntityId,
            },
        };

        manifestGeneratorProviderMock
            .Setup(x => x.Get(It.IsAny<ManifestInfo>()))
            .Returns(manifestGeneratorMock.Object);

        manifestGeneratorMock
            .Setup(x => x.GenerateJsonDocument(It.IsAny<SbomPackage>()))
            .Returns(generationResult);
    }

    [TestCleanup]
    public void AfterEach()
    {
        manifestGeneratorMock.VerifyAll();
        manifestGeneratorProviderMock.VerifyAll();
        manifestToolJsonSerializerMock.VerifyAll();
        loggerMock.VerifyAll();
        sbomPackageDetailsRecorderMock.VerifyAll();
        sbomConfigMock.VerifyAll();
    }

    [TestMethod]
    [DataRow(null, true)]
    [DataRow(new string[0], true)]
    [DataRow(new[] { "a", "b", "c" }, true)]
    public async Task GenerateJson_RecordsExpectedDependencies(string[] testCase, bool expectNullDependency)
    {
        var sbomConfigs = new[] { sbomConfigMock.Object };
        var packageInfo = new SbomPackage
        {
            PackageName = "TestPackage",
            PackageVersion = "1.0.0",
            PackageUrl = "pkg:example/testpackage@1.0.0"
        };
        var resultChannel = Channel.CreateUnbounded<JsonDocWithSerializer>();
        var errorsChannel = Channel.CreateUnbounded<FileValidationResult>();

        if (testCase is not null)
        {
            generationResult.ResultMetadata.DependOn = testCase.ToList();
        }

        sbomPackageDetailsRecorderMock.Setup(m => m.RecordPackageId(TestEntityId, null));

        await testSubject.GenerateJson(sbomConfigs, packageInfo, resultChannel, errorsChannel);
    }
}
