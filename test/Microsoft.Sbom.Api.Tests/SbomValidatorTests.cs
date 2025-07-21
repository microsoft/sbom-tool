// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Tests;

[TestClass]
public class SbomValidatorTests
{
    private Mock<IWorkflow<SbomParserBasedValidationWorkflow>> workflowMock;
    private Mock<IRecorder> recorderMock;
    private Mock<IEnumerable<ConfigValidator>> configValidatorsMock;
    private Mock<IConfiguration> configurationMock;
    private Mock<ISbomConfigProvider> sbomConfigProviderMock;
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<ISbomConfig> sbomConfigMock;
    private SbomValidator sbomValidator;

    // Common test data
    private readonly string buildDropPath = "/test/drop";
    private readonly string outputPathFile = "/test/output.json";
    private readonly string outputPathDirectory = "/test/output";
    private readonly List<SbomSpecification> specifications = new List<SbomSpecification> { new SbomSpecification("SPDX", "2.2") };
    private readonly string manifestDirPath = "/test/manifest";
    private readonly ManifestInfo manifestInfo = Constants.TestManifestInfo;
    private readonly string manifestJsonPath = "/test/manifest/manifest.json";

    [TestInitialize]
    public void Init()
    {
        workflowMock = new Mock<IWorkflow<SbomParserBasedValidationWorkflow>>(MockBehavior.Strict);
        recorderMock = new Mock<IRecorder>(MockBehavior.Strict);
        configValidatorsMock = new Mock<IEnumerable<ConfigValidator>>(MockBehavior.Strict);
        configurationMock = new Mock<IConfiguration>(MockBehavior.Strict);
        sbomConfigProviderMock = new Mock<ISbomConfigProvider>(MockBehavior.Strict);
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        sbomConfigMock = new Mock<ISbomConfig>(MockBehavior.Strict);

        sbomValidator = new SbomValidator(
            workflowMock.Object,
            recorderMock.Object,
            configValidatorsMock.Object,
            configurationMock.Object,
            sbomConfigProviderMock.Object,
            fileSystemUtilsMock.Object);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        workflowMock.VerifyAll();
        recorderMock.VerifyAll();
        configValidatorsMock.VerifyAll();
        configurationMock.VerifyAll();
        sbomConfigProviderMock.VerifyAll();
        fileSystemUtilsMock.VerifyAll();
        sbomConfigMock.VerifyAll();
    }

    [TestMethod]
    public async Task ValidateSbomAsync_WithNoErrorsAndNoExceptions_ReturnsTrue()
    {
        var errors = new List<FileValidationResult>();
        var exceptions = new List<Exception>();

        configValidatorsMock.Setup(cv => cv.GetEnumerator()).Returns(new List<ConfigValidator>().GetEnumerator());

        configurationMock.Setup(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo> { manifestInfo }
        });

        sbomConfigProviderMock.Setup(scp => scp.Get(manifestInfo)).Returns(sbomConfigMock.Object);
        sbomConfigMock.Setup(sc => sc.ManifestJsonFilePath).Returns(manifestJsonPath);

        fileSystemUtilsMock.Setup(fs => fs.FileExists(manifestJsonPath)).Returns(true);
        workflowMock.Setup(w => w.RunAsync()).ReturnsAsync(true);

        recorderMock.Setup(r => r.FinalizeAndLogTelemetryAsync()).Returns(Task.CompletedTask);
        recorderMock.Setup(r => r.Errors).Returns(errors);
        recorderMock.Setup(r => r.Exceptions).Returns(exceptions);

        var result = await sbomValidator.ValidateSbomAsync(buildDropPath, outputPathFile, specifications, manifestDirPath);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(0, result.Errors.Count);
    }

    [TestMethod]
    public async Task ValidateSbomAsync_WithErrorsButNoExceptions_ReturnsFalse()
    {
        var errors = new List<FileValidationResult>
        {
            new FileValidationResult { ErrorType = ErrorType.MissingFile, Path = "/test/missing.txt" }
        };
        var exceptions = new List<Exception>();

        configValidatorsMock.Setup(cv => cv.GetEnumerator()).Returns(new List<ConfigValidator>().GetEnumerator());

        configurationMock.Setup(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo> { manifestInfo }
        });

        sbomConfigProviderMock.Setup(scp => scp.Get(manifestInfo)).Returns(sbomConfigMock.Object);
        sbomConfigMock.Setup(sc => sc.ManifestJsonFilePath).Returns(manifestJsonPath);

        fileSystemUtilsMock.Setup(fs => fs.FileExists(manifestJsonPath)).Returns(true);
        workflowMock.Setup(w => w.RunAsync()).ReturnsAsync(true);

        recorderMock.Setup(r => r.FinalizeAndLogTelemetryAsync()).Returns(Task.CompletedTask);
        recorderMock.Setup(r => r.Errors).Returns(errors);
        recorderMock.Setup(r => r.Exceptions).Returns(exceptions);

        var result = await sbomValidator.ValidateSbomAsync(buildDropPath, outputPathFile, specifications, manifestDirPath);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(1, result.Errors.Count);
    }

    [TestMethod]
    public async Task ValidateSbomAsync_WithNoErrorsButWithExceptions_ReturnsFalse()
    {
        var errors = new List<FileValidationResult>();
        var exceptions = new List<Exception>
        {
            new InvalidOperationException("Cannot write to directory path")
        };

        configValidatorsMock.Setup(cv => cv.GetEnumerator()).Returns(new List<ConfigValidator>().GetEnumerator());

        configurationMock.Setup(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo> { manifestInfo }
        });

        sbomConfigProviderMock.Setup(scp => scp.Get(manifestInfo)).Returns(sbomConfigMock.Object);
        sbomConfigMock.Setup(sc => sc.ManifestJsonFilePath).Returns(manifestJsonPath);

        fileSystemUtilsMock.Setup(fs => fs.FileExists(manifestJsonPath)).Returns(true);
        workflowMock.Setup(w => w.RunAsync()).ReturnsAsync(true);

        recorderMock.Setup(r => r.FinalizeAndLogTelemetryAsync()).Returns(Task.CompletedTask);
        recorderMock.Setup(r => r.Errors).Returns(errors);
        recorderMock.Setup(r => r.Exceptions).Returns(exceptions);

        var result = await sbomValidator.ValidateSbomAsync(buildDropPath, outputPathDirectory, specifications, manifestDirPath);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(0, result.Errors.Count); // No validation errors, but should still fail due to exception
    }

    [TestMethod]
    public async Task ValidateSbomAsync_WithBothErrorsAndExceptions_ReturnsFalse()
    {
        var errors = new List<FileValidationResult>
        {
            new FileValidationResult { ErrorType = ErrorType.MissingFile, Path = "/test/missing.txt" }
        };
        var exceptions = new List<Exception>
        {
            new InvalidOperationException("Cannot write to directory path")
        };

        configValidatorsMock.Setup(cv => cv.GetEnumerator()).Returns(new List<ConfigValidator>().GetEnumerator());

        configurationMock.Setup(c => c.ManifestInfo).Returns(new ConfigurationSetting<IList<ManifestInfo>>
        {
            Value = new List<ManifestInfo> { manifestInfo }
        });

        sbomConfigProviderMock.Setup(scp => scp.Get(manifestInfo)).Returns(sbomConfigMock.Object);
        sbomConfigMock.Setup(sc => sc.ManifestJsonFilePath).Returns(manifestJsonPath);

        fileSystemUtilsMock.Setup(fs => fs.FileExists(manifestJsonPath)).Returns(true);
        workflowMock.Setup(w => w.RunAsync()).ReturnsAsync(true);

        recorderMock.Setup(r => r.FinalizeAndLogTelemetryAsync()).Returns(Task.CompletedTask);
        recorderMock.Setup(r => r.Errors).Returns(errors);
        recorderMock.Setup(r => r.Exceptions).Returns(exceptions);

        var result = await sbomValidator.ValidateSbomAsync(buildDropPath, outputPathDirectory, specifications, manifestDirPath);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(1, result.Errors.Count);
    }
}
