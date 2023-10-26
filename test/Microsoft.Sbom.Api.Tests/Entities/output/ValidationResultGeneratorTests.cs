// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Entities.Output.Tests;

[TestClass]
public class ValidationResultGeneratorTests
{
    [TestMethod]
    public void ValidationResultGenerator_ShouldGenerateReportWithoutFailures()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: false);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(12)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Success, validationResultOutput.Result);
        Assert.AreEqual(0, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(0, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(2, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    [TestMethod]
    public void ValidationResultGenerator_ShouldGenerateReportWithoutFailuresIfIgnoreMissing()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(12)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Success, validationResultOutput.Result);
        Assert.AreEqual(0, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(0, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(2, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    [TestMethod]
    public void ValidationResultGenerator_IncorrectHashShouldCauseFailure()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: false);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child2/grandchild1/file9",
            ErrorType = ErrorType.InvalidHash
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(11)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Failure, validationResultOutput.Result);
        Assert.AreEqual(1, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(1, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(11, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(2, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    [TestMethod]
    public void ValidationResultGenerator_MissingFileShouldCauseFailure()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: false);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child2/grandchild2/file10",
            ErrorType = ErrorType.MissingFile
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(11)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Failure, validationResultOutput.Result);
        Assert.AreEqual(1, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(1, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(11, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(2, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    [TestMethod]
    public void ValidationResultGenerator_MissingFileShouldNotCauseFailureIfIgnoreMissing()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child2/grandchild2/file10",
            ErrorType = ErrorType.MissingFile
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(12)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Success, validationResultOutput.Result);
        Assert.AreEqual(0, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(0, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(3, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    [TestMethod]
    public void ValidationResultGenerator_ShouldFailOnlyOnWrongHashIfIgnoreMissing()
    {
        var manifestData = GetDefaultManifestData();
        var configurationMock = GetDefaultConfigurationMock(ignoreMissing: true);

        var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);
        var failures = new List<FileValidationResult>();

        failures.Add(new FileValidationResult()
        {
            Path = "/_manifest/manifestjson",
            ErrorType = ErrorType.ManifestFolder
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child5/file8",
            ErrorType = ErrorType.FilteredRootPath
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child2/grandchild2/file10",
            ErrorType = ErrorType.MissingFile
        });

        failures.Add(new FileValidationResult()
        {
            Path = "/child2/grandchild1/file9",
            ErrorType = ErrorType.InvalidHash
        });

        var validationResultOutput = validationResultGenerator
            .WithTotalFilesInManifest(manifestData.Count)
            .WithSuccessCount(11)
            .WithTotalDuration(TimeSpan.FromSeconds(5))
            .WithValidationResults(failures)
            .Build();

        Assert.AreEqual(Result.Failure, validationResultOutput.Result);
        Assert.AreEqual(1, validationResultOutput.ValidationErrors.Count);
        Assert.AreEqual(12, validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest);
        Assert.AreEqual(1, validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount);
        Assert.AreEqual(11, validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount);
        Assert.AreEqual(3, validationResultOutput.Summary.ValidationTelemetery.FilesSkippedCount);
    }

    private static Mock<IConfiguration> GetDefaultConfigurationMock(bool ignoreMissing)
    {
        var configurationMock = new Mock<IConfiguration>();
        configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
        configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
        configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
        configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
        configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
        configurationMock.SetupGet(c => c.ValidateSignature).Returns(new ConfigurationSetting<bool> { Value = true });
        configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = ignoreMissing });
        configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        return configurationMock;
    }

    private static ManifestData GetDefaultManifestData()
    {
        IDictionary<string, Checksum[]> hashDictionary = new Dictionary<string, Checksum[]>
        {
            ["/_manifest/manifestjson"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/_manifest/manifestjsonhash" } },
            ["/child1/file1"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child1/file1hash" } },
            ["/child1/file2"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child1/file2hash" } },
            ["/child2/file3"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file3hash" } },
            ["/child2/file4"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file4hash" } },
            ["/child2/file5"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file5hash" } },
            ["/child3/file11"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child3/file11hash" } },
            ["/child3/file12"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child3/file12hash" } },
            ["/child2/grandchild1/file6"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file6hash" } },
            ["/child5/file8"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child5/file8hash" } },
            ["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "incorrectHash" } },
            ["/child2/grandchild2/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "missingfile" } }
        };
        return new ManifestData
        {
            HashesMap = new ConcurrentDictionary<string, Checksum[]>(hashDictionary, StringComparer.InvariantCultureIgnoreCase),
            Count = hashDictionary.Keys.Count
        };
    }
}
