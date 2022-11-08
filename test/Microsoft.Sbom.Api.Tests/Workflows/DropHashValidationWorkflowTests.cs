// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;
using Microsoft.Sbom.Workflows;

namespace Microsoft.Sbom.Api.Workflows.Tests
{
    [TestClass]
    public class DropHashValidationWorkflowTests : ValidationWorkflowTestsBase
    {
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
        private readonly Mock<ISbomPackageDetailsRecorder> recorder = new Mock<ISbomPackageDetailsRecorder>();
        private readonly Mock<IOSUtils> mockOSUtils = new Mock<IOSUtils>();
        private readonly Mock<IFileSystemUtilsExtension> fileSystemExtension = new Mock<IFileSystemUtilsExtension>();

        [TestInitialize]
        public void TestInitialize()
        {
            fileSystemExtension.Setup(f => f.IsTargetPathInSource(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        }

        [TestMethod]
        public async Task DropHashValidationWorkflowTestAsync_ReturnsSuccessAndValidationFailures_Succeeds()
        {
            Mock<IFileSystemUtils> fileSystemMock = GetDefaultFileSystemMock();
            var manifestData = GetDefaultManifestData();

            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                    .Returns((string fileName, AlgorithmName[] algos) =>
                                new Checksum[]
                                {
                                    new Checksum
                                    {
                                        ChecksumValue = $"{fileName}hash",
                                        Algorithm = Constants.DefaultHashAlgorithmName
                                    }
                                });

            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.Is<string>(a => a == "/root/child2/grandchild1/file10"),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                                 .Throws(new FileNotFoundException());

            var configurationMock = new Mock<IConfiguration>();
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
            configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
            configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(true);

            var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

            var outputWriterMock = new Mock<IOutputWriter>();

            var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
            rootFileFilterMock.Init();

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();
            var fileHasher = new FileHasher(
                               hashCodeGeneratorMock.Object,
                               new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemExtension.Object),
                               mockLogger.Object,
                               configurationMock.Object,
                               new Mock<ISbomConfigProvider>().Object,
                               new ManifestGeneratorProvider(null),
                               new FileTypeUtils())
            {
                ManifestData = manifestData
            };

            var recorderMock = new Mock<IRecorder>().Object;

            var workflow = new SBOMValidationWorkflow(
                configurationMock.Object,
                new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                new ManifestFolderFilterer(
                    manifestFilterMock,
                    mockLogger.Object),
                new ChannelUtils(),
                fileHasher,
                new HashValidator(configurationMock.Object, manifestData),
                manifestData,
                validationResultGenerator,
                outputWriterMock.Object,
                mockLogger.Object,
                signValidatorMock.Object,
                new ManifestFileFilterer(
                    manifestData,
                    rootFileFilterMock,
                    configurationMock.Object,
                    mockLogger.Object,
                    fileSystemMock.Object),
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsFalse(result);

            var nodeValidationResults = validationResultGenerator.NodeValidationResults;

            var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
            Assert.AreEqual(1, additionalFileErrors.Count);
            Assert.AreEqual("/child2/grandchild1/file7", additionalFileErrors.First().Path);

            var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
            Assert.AreEqual(1, missingFileErrors.Count);
            Assert.AreEqual("/child2/grandchild2/file10", missingFileErrors.First().Path);

            var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
            Assert.AreEqual(1, invalidHashErrors.Count);
            Assert.AreEqual("/child2/grandchild1/file9", invalidHashErrors.First().Path);

            var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
            Assert.AreEqual(1, otherErrors.Count);
            Assert.AreEqual("/child2/grandchild1/file10", otherErrors.First().Path);

            configurationMock.VerifyAll();
            signValidatorMock.VerifyAll();
            fileSystemMock.VerifyAll();
        }

        [TestMethod]
        public async Task DropHashValidationWorkflowTestAsync_NoErrors()
        {
            Mock<IFileSystemUtils> fileSystemMock = GetDefaultFileSystemMock();

            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var recorderMock = new Mock<IRecorder>().Object;
            var manifestData = GetDefaultManifestData();

            manifestData.HashesMap["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file9hash" } };
            manifestData.HashesMap["/child2/grandchild1/file7"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file7hash" } };
            manifestData.HashesMap["/child2/grandchild1/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file10hash" } };

            manifestData.HashesMap.Remove("/child2/grandchild2/file10");

            var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                                 .Returns((string fileName, AlgorithmName[] algos) =>
                                             new Checksum[]
                                             {
                                                 new Checksum
                                                 {
                                                     ChecksumValue = $"{fileName}hash",
                                                     Algorithm = Constants.DefaultHashAlgorithmName
                                                 }
                                             });

            var configurationMock = new Mock<IConfiguration>();
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
            configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
            configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(true);

            var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

            var outputWriterMock = new Mock<IOutputWriter>();

            var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
            rootFileFilterMock.Init();

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();
            var fileHasher = new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemExtension.Object),
                mockLogger.Object,
                configurationMock.Object,
                new Mock<ISbomConfigProvider>().Object,
                new ManifestGeneratorProvider(null),
                new FileTypeUtils())
            {
                ManifestData = manifestData
            };

            var workflow = new SBOMValidationWorkflow(
                configurationMock.Object,
                new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                new ManifestFolderFilterer(
                    manifestFilterMock,
                    mockLogger.Object),
                new ChannelUtils(),
                fileHasher,
                new HashValidator(configurationMock.Object, manifestData),
                manifestData,
                validationResultGenerator,
                outputWriterMock.Object,
                mockLogger.Object,
                signValidatorMock.Object,
                new ManifestFileFilterer(
                    manifestData,
                    rootFileFilterMock,
                    configurationMock.Object,
                    mockLogger.Object,
                    fileSystemMock.Object),
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsTrue(result);

            var nodeValidationResults = validationResultGenerator.NodeValidationResults;

            var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
            Assert.AreEqual(0, additionalFileErrors.Count);

            var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
            Assert.AreEqual(0, missingFileErrors.Count);

            var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
            Assert.AreEqual(0, invalidHashErrors.Count);

            var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
            Assert.AreEqual(0, otherErrors.Count);

            configurationMock.VerifyAll();
            signValidatorMock.VerifyAll();
            fileSystemMock.VerifyAll();
        }

        [TestMethod]
        public async Task DropHashValidationWorkflowTestAsync_IgnoreMissingTrue()
        {
            Mock<IFileSystemUtils> fileSystemMock = GetDefaultFileSystemMock();

            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var recorderMock = new Mock<IRecorder>().Object;
            var manifestData = GetDefaultManifestData();

            manifestData.HashesMap["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file9hash" } };
            manifestData.HashesMap["/child2/grandchild1/file7"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file7hash" } };
            manifestData.HashesMap["/child2/grandchild1/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file10hash" } };

            var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                                 .Returns((string fileName, AlgorithmName[] algos) =>
                                             new Checksum[]
                                             {
                                                 new Checksum
                                                 {
                                                     ChecksumValue = $"{fileName}hash",
                                                     Algorithm = Constants.DefaultHashAlgorithmName
                                                 }
                                             });

            var configurationMock = new Mock<IConfiguration>();
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
            configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
            configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = true });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(true);

            var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

            var outputWriterMock = new Mock<IOutputWriter>();

            var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
            rootFileFilterMock.Init();

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();
            var fileHasher = new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemExtension.Object),
                mockLogger.Object,
                configurationMock.Object,
                new Mock<ISbomConfigProvider>().Object,
                new ManifestGeneratorProvider(null),
                new FileTypeUtils())
            {
                ManifestData = manifestData
            };

            var workflow = new SBOMValidationWorkflow(
                configurationMock.Object,
                new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                new ManifestFolderFilterer(
                    manifestFilterMock,
                    mockLogger.Object),
                new ChannelUtils(),
                fileHasher,
                new HashValidator(configurationMock.Object, manifestData),
                manifestData,
                validationResultGenerator,
                outputWriterMock.Object,
                mockLogger.Object,
                signValidatorMock.Object,
                new ManifestFileFilterer(
                    manifestData,
                    rootFileFilterMock,
                    configurationMock.Object,
                    mockLogger.Object,
                    fileSystemMock.Object),
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsTrue(result);

            var nodeValidationResults = validationResultGenerator.NodeValidationResults;

            var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
            Assert.AreEqual(0, additionalFileErrors.Count);

            var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
            Assert.AreEqual(1, missingFileErrors.Count);

            var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
            Assert.AreEqual(0, invalidHashErrors.Count);

            var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
            Assert.AreEqual(0, otherErrors.Count);

            configurationMock.VerifyAll();
            signValidatorMock.VerifyAll();
            fileSystemMock.VerifyAll();
        }

        [TestMethod]
        public async Task DropHashValidationWorkflowTestAsync_IgnoreMissingTrueAndInvalidHashShouldFail()
        {
            Mock<IFileSystemUtils> fileSystemMock = GetDefaultFileSystemMock();
            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var recorderMock = new Mock<IRecorder>().Object;
            var manifestData = GetDefaultManifestData();

            manifestData.HashesMap["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file9hash" } };
            manifestData.HashesMap["/child2/grandchild1/file7"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file7hash" } };
            manifestData.HashesMap["/child2/grandchild1/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file10hash" } };

            var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                                 .Returns((string fileName, AlgorithmName[] algos) =>
                                             new Checksum[]
                                             {
                                                 new Checksum
                                                 {
                                                     ChecksumValue = $"{fileName}hash",
                                                     Algorithm = Constants.DefaultHashAlgorithmName
                                                 }
                                             });

            var configurationMock = new Mock<IConfiguration>();
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
            configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
            configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = true });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(true);

            var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

            var outputWriterMock = new Mock<IOutputWriter>();

            var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
            rootFileFilterMock.Init();

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();
            var fileHasher = new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemExtension.Object),
                mockLogger.Object,
                configurationMock.Object,
                new Mock<ISbomConfigProvider>().Object,
                new ManifestGeneratorProvider(null),
                new FileTypeUtils())
            {
                ManifestData = manifestData
            };

            var workflow = new SBOMValidationWorkflow(
                configurationMock.Object,
                new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                new ManifestFolderFilterer(
                    manifestFilterMock,
                    mockLogger.Object),
                new ChannelUtils(),
                fileHasher,
                new HashValidator(configurationMock.Object, manifestData),
                manifestData,
                validationResultGenerator,
                outputWriterMock.Object,
                mockLogger.Object,
                signValidatorMock.Object,
                new ManifestFileFilterer(
                    manifestData,
                    rootFileFilterMock,
                    configurationMock.Object,
                    mockLogger.Object,
                    fileSystemMock.Object),
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsTrue(result);

            var nodeValidationResults = validationResultGenerator.NodeValidationResults;

            var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
            Assert.AreEqual(0, additionalFileErrors.Count);

            var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
            Assert.AreEqual(1, missingFileErrors.Count);

            var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
            Assert.AreEqual(0, invalidHashErrors.Count);

            var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
            Assert.AreEqual(0, otherErrors.Count);

            configurationMock.VerifyAll();
            signValidatorMock.VerifyAll();
            fileSystemMock.VerifyAll();
        }

        [TestMethod]
        public async Task DropHashValidationWorkflowTestAsync_IgnoreMissingFalse()
        {
            Mock<IFileSystemUtils> fileSystemMock = GetDefaultFileSystemMock();
            fileSystemMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var recorderMock = new Mock<IRecorder>().Object;
            var manifestData = GetDefaultManifestData();

            manifestData.HashesMap["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file9hash" } };
            manifestData.HashesMap["/child2/grandchild1/file7"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file7hash" } };
            manifestData.HashesMap["/child2/grandchild1/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file10hash" } };

            var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
            hashCodeGeneratorMock.Setup(h => h.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
                                 .Returns((string fileName, AlgorithmName[] algos) =>
                                             new Checksum[]
                                             {
                                                 new Checksum
                                                 {
                                                     ChecksumValue = $"{fileName}hash",
                                                     Algorithm = Constants.DefaultHashAlgorithmName
                                                 }
                                             });

            var configurationMock = new Mock<IConfiguration>();
            configurationMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "/root" });
            configurationMock.SetupGet(c => c.ManifestDirPath).Returns(new ConfigurationSetting<string> { Value = PathUtils.Join("/root", "_manifest") });
            configurationMock.SetupGet(c => c.Parallelism).Returns(new ConfigurationSetting<int> { Value = 3 });
            configurationMock.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });
            configurationMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "child1;child2;child3" });
            configurationMock.SetupGet(c => c.IgnoreMissing).Returns(new ConfigurationSetting<bool> { Value = false });
            configurationMock.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
            configurationMock.SetupGet(c => c.FollowSymlinks).Returns(new ConfigurationSetting<bool> { Value = true });

            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(true);

            var validationResultGenerator = new ValidationResultGenerator(configurationMock.Object);

            var outputWriterMock = new Mock<IOutputWriter>();

            var rootFileFilterMock = new DownloadedRootPathFilter(configurationMock.Object, fileSystemMock.Object, mockLogger.Object);
            rootFileFilterMock.Init();

            var manifestFilterMock = new ManifestFolderFilter(configurationMock.Object, fileSystemMock.Object, mockOSUtils.Object);
            manifestFilterMock.Init();
            var fileHasher = new FileHasher(
                hashCodeGeneratorMock.Object,
                new SbomToolManifestPathConverter(configurationMock.Object, mockOSUtils.Object, fileSystemMock.Object, fileSystemExtension.Object),
                mockLogger.Object,
                configurationMock.Object,
                new Mock<ISbomConfigProvider>().Object,
                new ManifestGeneratorProvider(null),
                new FileTypeUtils())
            {
                ManifestData = manifestData
            };

            var workflow = new SBOMValidationWorkflow(
                configurationMock.Object,
                new DirectoryWalker(fileSystemMock.Object, mockLogger.Object, configurationMock.Object),
                new ManifestFolderFilterer(
                    manifestFilterMock,
                    mockLogger.Object),
                new ChannelUtils(),
                fileHasher,
                new HashValidator(configurationMock.Object, manifestData),
                manifestData,
                validationResultGenerator,
                outputWriterMock.Object,
                mockLogger.Object,
                signValidatorMock.Object,
                new ManifestFileFilterer(
                    manifestData,
                    rootFileFilterMock,
                    configurationMock.Object,
                    mockLogger.Object,
                    fileSystemMock.Object),
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsFalse(result);

            var nodeValidationResults = validationResultGenerator.NodeValidationResults;

            var additionalFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.AdditionalFile).ToList();
            Assert.AreEqual(0, additionalFileErrors.Count);

            var missingFileErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.MissingFile).ToList();
            Assert.AreEqual(1, missingFileErrors.Count);

            var invalidHashErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.InvalidHash).ToList();
            Assert.AreEqual(0, invalidHashErrors.Count);

            var otherErrors = nodeValidationResults.Where(a => a.ErrorType == ErrorType.Other).ToList();
            Assert.AreEqual(0, otherErrors.Count);

            configurationMock.VerifyAll();
            signValidatorMock.VerifyAll();
            fileSystemMock.VerifyAll();
        }

        [TestMethod]
        public async Task SignValidationFailsDoesntRunWorkflow_Fails()
        {
            var signValidatorMock = new Mock<ISignValidator>();
            signValidatorMock.Setup(s => s.Validate()).Returns(false);
            var recorderMock = new Mock<IRecorder>().Object;

            var workflow = new SBOMValidationWorkflow(
                null,
                null,
                null,
                null,
                null,
                null,
                GetDefaultManifestData(),
                null,
                null,
                mockLogger.Object,
                signValidatorMock.Object,
                null,
                recorderMock);

            var result = await workflow.RunAsync();
            Assert.IsFalse(result);
            signValidatorMock.VerifyAll();
        }
    }
}