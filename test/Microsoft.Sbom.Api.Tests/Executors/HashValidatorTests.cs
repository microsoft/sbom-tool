﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;

namespace Microsoft.Sbom.Api.Executors.Tests
{
    [TestClass]
    public class HashValidatorTests
    {
        [TestMethod]
        public async Task HashValidatorTest_ValidHash_SucceedsAsync()
        {
            var fileList = new HashSet<string>()
            {
                "TEST1",
                "TEST2",
                "TEST3"
            };
            ConcurrentDictionary<string, Checksum[]> hashDict = new ConcurrentDictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var file in fileList)
            {
                hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hash" } };
            }

            var configuration = new Mock<IConfiguration>();
            configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

            var files = Channel.CreateUnbounded<InternalSBOMFileInfo>();
            foreach (var file in fileList)
            {
                await files.Writer.WriteAsync(new InternalSBOMFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
            }

            files.Writer.Complete();

            var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
            var validationResults = validator.Validate(files);

            await foreach (FileValidationResult output in validationResults.output.ReadAllAsync())
            {
                Assert.IsTrue(fileList.Remove(output.Path));
            }

            Assert.AreEqual(0, fileList.Count);
            Assert.IsTrue(validationResults.errors.Count == 0);
        }

        [TestMethod]
        public async Task HashValidatorTest_InValidHash_ReturnsValidationErrorAsync()
        {
            var fileList = new HashSet<string>()
            {
                "TEST1",
                "TEST2",
                "TEST3"
            };

            ConcurrentDictionary<string, Checksum[]> hashDict = new ConcurrentDictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var file in fileList)
            {
                hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hashInvalid" } };
            }

            var configuration = new Mock<IConfiguration>();
            configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

            var files = Channel.CreateUnbounded<InternalSBOMFileInfo>();
            foreach (var file in fileList)
            {
                await files.Writer.WriteAsync(new InternalSBOMFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
            }

            files.Writer.Complete();

            var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
            var validationResults = validator.Validate(files);

            await foreach (FileValidationResult output in validationResults.output.ReadAllAsync())
            {
                Assert.IsTrue(fileList.Remove(output.Path));
            }

            await foreach (FileValidationResult error in validationResults.errors.ReadAllAsync())
            {
                Assert.AreEqual(ErrorType.InvalidHash, error.ErrorType);
                Assert.IsTrue(fileList.Remove(error.Path));
            }

            Assert.AreEqual(0, fileList.Count);
        }

        [TestMethod]
        public async Task HashValidatorTest_AdditionalFile_ReturnsAdditionalFileFailureAsync()
        {
            var fileList = new HashSet<string>()
            {
                "TEST1",
                "TEST2",
                "TEST3"
            };

            ConcurrentDictionary<string, Checksum[]> hashDict = new ConcurrentDictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var file in fileList)
            {
                hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hash" } };
            }

            var configuration = new Mock<IConfiguration>();
            configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

            var files = Channel.CreateUnbounded<InternalSBOMFileInfo>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            foreach (var file in fileList)
            {
                await files.Writer.WriteAsync(new InternalSBOMFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
            }

            // Additional file.
            await files.Writer.WriteAsync(new InternalSBOMFileInfo { Path = "TEST4", Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"TEST4_hash" } } });

            files.Writer.Complete();
            errors.Writer.Complete();

            var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
            var validationResults = validator.Validate(files);

            await foreach (FileValidationResult error in validationResults.errors.ReadAllAsync())
            {
                Assert.AreEqual(ErrorType.AdditionalFile, error.ErrorType);
                Assert.AreEqual("TEST4", error.Path);
            }

            await foreach (FileValidationResult output in validationResults.output.ReadAllAsync())
            {
                Assert.IsTrue(fileList.Remove(output.Path));
            }

            Assert.AreEqual(0, fileList.Count);
        }
    }
}