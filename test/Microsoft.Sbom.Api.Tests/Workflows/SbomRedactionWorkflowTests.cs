// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
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
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<ValidatedSBOMFactory> validatedSBOMFactoryMock;
    private Mock<ISbomRedactor> sbomRedactorMock;
    private SbomRedactionWorkflow testSubject;

    private const string SbomPathStub = "sbom-path";
    private const string SbomDirStub = "sbom-dir";
    private const string OutDirStub = "out-dir";
    private const string OutPathStub = "out-path";
    private const string SbomFileNameStub = "sbom-name";

    [TestInitialize]
    public void Init()
    {
        mockLogger = new Mock<ILogger>();
        configurationMock = new Mock<IConfiguration>();
        fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        validatedSBOMFactoryMock = new Mock<ValidatedSBOMFactory>();
        sbomRedactorMock = new Mock<ISbomRedactor>();
        testSubject = new SbomRedactionWorkflow(
            mockLogger.Object,
            configurationMock.Object,
            fileSystemUtilsMock.Object,
            validatedSBOMFactoryMock.Object,
            sbomRedactorMock.Object);
    }

    [TestCleanup]
    public void Reset()
    {
        mockLogger.VerifyAll();
        fileSystemUtilsMock.VerifyAll();
        configurationMock.VerifyAll();
        validatedSBOMFactoryMock.VerifyAll();
        sbomRedactorMock.VerifyAll();
    }

    [TestMethod]
    public async Task SbomRedactionWorkflow_FailsOnNoSbomsProvided()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(testSubject.RunAsync);
    }

    [TestMethod]
    public async Task SbomRedactionWorkflow_FailsOnMatchingInputOutputDirs()
    {
        configurationMock.SetupGet(c => c.SbomDir).Returns(new ConfigurationSetting<string> { Value = SbomDirStub });
        configurationMock.SetupGet(c => c.OutputPath).Returns(new ConfigurationSetting<string> { Value = SbomDirStub });
        fileSystemUtilsMock.Setup(m => m.DirectoryExists(SbomDirStub)).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetFullPath(SbomDirStub)).Returns(SbomDirStub).Verifiable();
        await Assert.ThrowsExceptionAsync<ArgumentException>(testSubject.RunAsync);
    }

    [TestMethod]
    public async Task SbomRedactionWorkflow_FailsOnExistingOutputSbom()
    {
        configurationMock.SetupGet(c => c.SbomPath).Returns(new ConfigurationSetting<string> { Value = SbomPathStub });
        configurationMock.SetupGet(c => c.OutputPath).Returns(new ConfigurationSetting<string> { Value = OutDirStub });
        fileSystemUtilsMock.Setup(m => m.FileExists(SbomPathStub)).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetDirectoryName(SbomPathStub)).Returns(SbomDirStub).Verifiable();
        fileSystemUtilsMock.Setup(m => m.DirectoryExists(OutDirStub)).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetFullPath(SbomDirStub)).Returns(SbomDirStub).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetFullPath(OutDirStub)).Returns(OutDirStub).Verifiable();

        // GetOutputPath
        fileSystemUtilsMock.Setup(m => m.GetFileName(SbomPathStub)).Returns(SbomFileNameStub).Verifiable();
        fileSystemUtilsMock.Setup(m => m.JoinPaths(OutDirStub, SbomFileNameStub)).Returns(OutPathStub).Verifiable();

        // Output already file exists
        fileSystemUtilsMock.Setup(m => m.FileExists(OutPathStub)).Returns(true).Verifiable();

        await Assert.ThrowsExceptionAsync<ArgumentException>(testSubject.RunAsync);
    }

    [TestMethod]
    public async Task SbomRedactionWorkflow_FailsOnInvalidSboms()
    {
        SetUpDirStructure();

        fileSystemUtilsMock.Setup(m => m.GetFilesInDirectory(SbomDirStub, true)).Returns(new string[] { SbomPathStub }).Verifiable();
        var validatedSbomMock = new Mock<IValidatedSBOM>();
        validatedSBOMFactoryMock.Setup(m => m.CreateValidatedSBOM(SbomPathStub)).Returns(validatedSbomMock.Object).Verifiable();
        var validationRes = new FormatValidationResults();
        validationRes.AggregateValidationStatus(FormatValidationStatus.NotValid);
        validatedSbomMock.Setup(m => m.GetValidationResults()).ReturnsAsync(validationRes).Verifiable();
        validatedSbomMock.Setup(m => m.Dispose()).Verifiable();

        await Assert.ThrowsExceptionAsync<InvalidDataException>(testSubject.RunAsync);
    }

    [TestMethod]
    public async Task SbomRedactionWorkflow_RunsRedactionOnValidSboms()
    {
        SetUpDirStructure();

        fileSystemUtilsMock.Setup(m => m.GetFilesInDirectory(SbomDirStub, true)).Returns(new string[] { SbomPathStub }).Verifiable();
        var validatedSbomMock = new Mock<IValidatedSBOM>();
        validatedSBOMFactoryMock.Setup(m => m.CreateValidatedSBOM(SbomPathStub)).Returns(validatedSbomMock.Object).Verifiable();
        var validationRes = new FormatValidationResults();
        validationRes.AggregateValidationStatus(FormatValidationStatus.Valid);
        validatedSbomMock.Setup(m => m.GetValidationResults()).ReturnsAsync(validationRes).Verifiable();
        var redactedContent = new FormatEnforcedSPDX2() { Name = "redacted" };
        sbomRedactorMock.Setup(m => m.RedactSBOMAsync(validatedSbomMock.Object)).ReturnsAsync(redactedContent).Verifiable();
        var outStream = new MemoryStream();
        fileSystemUtilsMock.Setup(m => m.OpenWrite(OutPathStub)).Returns(outStream).Verifiable();
        validatedSbomMock.Setup(m => m.Dispose()).Verifiable();

        var result = await testSubject.RunAsync();
        Assert.IsTrue(result);
        var redactedResult = Encoding.ASCII.GetString(outStream.ToArray());
        Assert.IsTrue(redactedResult.Contains(@"""name"":""redacted"""));
    }

    [DataRow("SPDX", "1.0")]
    [DataRow("SPDX", "3.0")]
    [DataRow("asdfi", "2.2")]
    [TestMethod]
    public async Task SbomRedactionWorkflow_FailsForInvalidManifestVersions(string name, string spdxVersion)
    {
        SetUpDirStructure();
        fileSystemUtilsMock.Setup(m => m.GetFilesInDirectory(SbomDirStub, true)).Returns(new string[] { SbomPathStub }).Verifiable();
        var invalidManifestInfo = new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo> { new ManifestInfo { Name = name, Version = spdxVersion } }
        };

        configurationMock.SetupGet(c => c.ManifestInfo).Returns(invalidManifestInfo);

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(testSubject.RunAsync);
    }

    private void SetUpDirStructure()
    {
        configurationMock.SetupGet(c => c.SbomDir).Returns(new ConfigurationSetting<string> { Value = SbomDirStub });
        configurationMock.SetupGet(c => c.OutputPath).Returns(new ConfigurationSetting<string> { Value = OutDirStub });
        fileSystemUtilsMock.Setup(m => m.DirectoryExists(SbomDirStub)).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(m => m.DirectoryExists(OutDirStub)).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetFullPath(SbomDirStub)).Returns(SbomDirStub).Verifiable();
        fileSystemUtilsMock.Setup(m => m.GetFullPath(OutDirStub)).Returns(OutDirStub).Verifiable();

        // GetOutputPath
        fileSystemUtilsMock.Setup(m => m.GetFileName(SbomPathStub)).Returns(SbomFileNameStub).Verifiable();
        fileSystemUtilsMock.Setup(m => m.JoinPaths(OutDirStub, SbomFileNameStub)).Returns(OutPathStub).Verifiable();

        // Output already file exists
        fileSystemUtilsMock.Setup(m => m.FileExists(OutPathStub)).Returns(false).Verifiable();
    }
}
