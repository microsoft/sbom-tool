// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Ninject;
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
        private StandardKernel kernel;
        private Mock<IWorkflow<SBOMGenerationWorkflow>> mockWorkflow;
        private Mock<IRecorder> mockRecorder;
        private RuntimeConfiguration runtimeConfiguration;

        [TestInitialize]
        public void Setup()
        {
            fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string p1, string p2) => Path.Join(p1, p2));

            kernel = new StandardKernel(new Bindings());
            kernel.Unbind<IWorkflow<SBOMGenerationWorkflow>>();
            kernel.Unbind<IRecorder>();
            kernel.Unbind<IFileSystemUtils>();

            kernel.Bind<IFileSystemUtils>().ToConstant(fileSystemMock.Object);
            generator = new SBOMGenerator(kernel, fileSystemMock.Object);
            mockWorkflow = new Mock<IWorkflow<SBOMGenerationWorkflow>>();
            mockRecorder = new Mock<IRecorder>();

            runtimeConfiguration = new RuntimeConfiguration
            {
                NamespaceUriBase = "https://base.uri"
            };
        }

        [TestMethod]
        public async Task When_GenerateSbomAsync_WithRecordedErrors_Then_PopulateEntityErrors()
        {
            var fileValidationResults = new List<FileValidationResult>();
            fileValidationResults.Add(new FileValidationResult() { Path = "random", ErrorType = ErrorType.Other });

            kernel.Bind<IWorkflow<SBOMGenerationWorkflow>>().ToMethod(x => mockWorkflow.Object).Named(nameof(SBOMGenerationWorkflow));
            kernel.Bind<IRecorder>().ToMethod(x => mockRecorder.Object).InSingletonScope();
            mockRecorder.Setup(c => c.Errors).Returns(fileValidationResults).Verifiable();
            mockWorkflow.Setup(c => c.RunAsync()).Returns(Task.FromResult(true)).Verifiable();

            var metadata = new SBOMMetadata()
            {
                PackageSupplier = "Contoso"
            };

            var result = await generator.GenerateSBOMAsync("rootPath", "compPath", metadata, configuration: runtimeConfiguration);

            Assert.AreEqual(1, result.Errors.Count);
            Assert.AreEqual(EntityErrorType.Other, result.Errors[0].ErrorType);
            Assert.AreEqual("random", ((FileEntity)result.Errors[0].Entity).Path);
            mockRecorder.Verify();
            mockWorkflow.Verify();
        }

        [TestMethod]
        public async Task When_GenerateSbomAsync_WithNoRecordedErrors_Then_EmptyEntityErrors()
        {
            kernel.Bind<IWorkflow<SBOMGenerationWorkflow>>().ToMethod(x => mockWorkflow.Object).Named(nameof(SBOMGenerationWorkflow));
            kernel.Bind<IRecorder>().ToMethod(x => mockRecorder.Object).InSingletonScope();
            mockRecorder.Setup(c => c.Errors).Returns(new List<FileValidationResult>()).Verifiable();
            mockWorkflow.Setup(c => c.RunAsync()).Returns(Task.FromResult(true)).Verifiable();

            var metadata = new SBOMMetadata()
            {
                PackageSupplier = "Contoso"
            };

            var result = await generator.GenerateSBOMAsync("rootPath", "compPath", metadata, configuration: runtimeConfiguration);

            Assert.AreEqual(0, result.Errors.Count);
            mockRecorder.Verify();
            mockWorkflow.Verify();
        }
    }
}
