// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using EntityErrorType = Microsoft.Sbom.Contracts.Enums.ErrorType;

namespace Microsoft.Sbom.Api.Tests
{
    [TestClass]
    public class SBOMGeneratorTest
    {
        private readonly Mock<IFileSystemUtils> fileSystemMock = new Mock<IFileSystemUtils>();
        private SBOMGenerator generator;
        private Mock<IWorkflow<SBOMGenerationWorkflow>> mockWorkflow;
        private Mock<IRecorder> mockRecorder;
        private Mock<ManifestGeneratorProvider> mockGeneratorProvider;
        private RuntimeConfiguration runtimeConfiguration;

        [TestInitialize]
        public void Setup()
        {
            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

            mockWorkflow = new Mock<IWorkflow<SBOMGenerationWorkflow>>();
            mockRecorder = new Mock<IRecorder>();
            mockGeneratorProvider = new Mock<ManifestGeneratorProvider>(null);

            runtimeConfiguration = new RuntimeConfiguration
            {
                NamespaceUriBase = "https://base.uri"
            };
        }

        [TestMethod]
        public async Task When_GenerateSbomAsync_WithRecordedErrors_Then_PopulateEntityErrors()
        {
            var fileValidationResults = new List<FileValidationResult>
            {
                new FileValidationResult() { Path = "random", ErrorType = ErrorType.Other }
            };

            mockRecorder.Setup(c => c.Errors).Returns(fileValidationResults).Verifiable();
            mockWorkflow.Setup(c => c.RunAsync()).Returns(Task.FromResult(true)).Verifiable();

            var metadata = new SBOMMetadata()
            {
                PackageSupplier = "Contoso"
            };

            generator = new SBOMGenerator(mockWorkflow.Object, mockGeneratorProvider.Object, mockRecorder.Object);
            var result = await generator.GenerateSBOMAsync();

            Assert.AreEqual(1, result.Errors.Count);
            Assert.AreEqual(EntityErrorType.Other, result.Errors[0].ErrorType);
            Assert.AreEqual("random", ((FileEntity)result.Errors[0].Entity).Path);
            mockRecorder.Verify();
            mockWorkflow.Verify();
        }

        [TestMethod]
        public async Task When_GenerateSbomAsync_WithNoRecordedErrors_Then_EmptyEntityErrors()
        {
            mockRecorder.Setup(c => c.Errors).Returns(new List<FileValidationResult>()).Verifiable();
            mockWorkflow.Setup(c => c.RunAsync()).Returns(Task.FromResult(true)).Verifiable();

            var metadata = new SBOMMetadata()
            {
                PackageSupplier = "Contoso"
            };

            generator = new SBOMGenerator(mockWorkflow.Object, mockGeneratorProvider.Object, mockRecorder.Object);
            var result = await generator.GenerateSBOMAsync();

            Assert.AreEqual(0, result.Errors.Count);
            mockRecorder.Verify();
            mockWorkflow.Verify();
        }
    }
}
