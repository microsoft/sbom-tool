// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;
using FileLocation = Microsoft.Sbom.Entities.FileLocation;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class ConcurrentSha256HashValidatorTests
{
    [TestMethod]
    public async Task ChecksumForConfiguredAlgorithm_MatchesAsync()
    {
        var validationResults = BuildValidator(AlgorithmName.SHA256).Validate(await BuildFilesAsync(AlgorithmName.SHA256));

        var validatedCount = 0;
        await foreach (var output in validationResults.output.ReadAllAsync())
        {
            validatedCount++;
            Assert.AreEqual("/test/file", output.Path);
        }

        var errorCount = 0;
        await foreach (var error in validationResults.errors.ReadAllAsync())
        {
            errorCount++;
        }

        Assert.AreEqual(1, validatedCount);
        Assert.AreEqual(0, errorCount);
    }

    [TestMethod]
    public async Task ChecksumMissingForConfiguredAlgorithm_DoesNotMatchAsync()
    {
        var validationResults = BuildValidator(AlgorithmName.SHA1).Validate(await BuildFilesAsync(AlgorithmName.SHA256));

        var validatedCount = 0;
        await foreach (var output in validationResults.output.ReadAllAsync())
        {
            validatedCount++;
        }

        var errorCount = 0;
        await foreach (var error in validationResults.errors.ReadAllAsync())
        {
            errorCount++;
            Assert.AreEqual(ErrorType.InvalidHash, error.ErrorType);
        }

        Assert.AreEqual(0, validatedCount);
        Assert.AreEqual(1, errorCount);
    }

    private static ConcurrentSha256HashValidator BuildValidator(AlgorithmName configuredAlgorithm)
    {
        var configuration = new Mock<IConfiguration>();
        configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = configuredAlgorithm });

        var fileHashes = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>(StringComparer.InvariantCultureIgnoreCase));
        return new ConcurrentSha256HashValidator(fileHashes, configuration.Object);
    }

    private static async Task<ChannelReader<InternalSbomFileInfo>> BuildFilesAsync(AlgorithmName checksumAlgorithm)
    {
        var files = Channel.CreateUnbounded<InternalSbomFileInfo>();
        foreach (var location in new[] { FileLocation.OnDisk, FileLocation.InSbomFile })
        {
            await files.Writer.WriteAsync(new InternalSbomFileInfo
            {
                Path = "/test/file",
                FileLocation = location,
                Checksum = new Checksum[] { new Checksum { Algorithm = checksumAlgorithm, ChecksumValue = "hash" } }
            });
        }

        files.Writer.Complete();
        return files;
    }
}
