// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Ninject;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config;

namespace Microsoft.Sbom.Api.Tests.Config
{
    [TestClass]
    public class ManifestToolCmdRunnerTests
    {
        [TestMethod]
        public async Task ManifestToolCmdRunner_Generate_BuildPathNoWritePermissions_AccessDenied()
        {
            var bindings = new Bindings();

            var runner = new ManifestToolCmdRunner(new StandardKernel(bindings));

            var fileSystemUtilsMock = new Mock<IFileSystemUtils>();
            fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(false).Verifiable();
            bindings.Rebind<IFileSystemUtils>().ToConstant(fileSystemUtilsMock.Object).InSingletonScope();

            var args = new GenerationArgs
            {
                BuildDropPath = "BuildDropPath"
            };

            await runner.Generate(args);

            Assert.IsTrue(runner.IsFailed);
            Assert.IsTrue(runner.IsAccessError);
        }

        [TestMethod]
        public async Task ManifestToolCmdRunner_Generate_Success()
        {
            var bindings = new Bindings();

            var runner = new ManifestToolCmdRunner(new StandardKernel(bindings));

            var fileSystemUtilsMock = new Mock<IFileSystemUtils>();
            fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemUtilsMock.Setup(f => f.DirectoryHasReadPermissions(It.IsAny<string>())).Returns(true).Verifiable();
            fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();

            fileSystemUtilsMock.Setup(f => f.GetRelativePath(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string r, string p) => PathUtils.GetRelativePath(r, p));

            var workflowMock = new Mock<IWorkflow>();
            workflowMock.Setup(f => f.RunAsync()).Returns(Task.FromResult(true)).Verifiable();

            bindings.Rebind<IFileSystemUtils>().ToConstant(fileSystemUtilsMock.Object).InSingletonScope();
            bindings.Rebind<IWorkflow>().ToConstant(workflowMock.Object).Named(nameof(SBOMGenerationWorkflow));

            var args = new GenerationArgs
            {
                BuildDropPath = "BuildDropPath",
                NamespaceUriBase = "https://base.uri"
            };

            await runner.Generate(args);

            Assert.IsFalse(runner.IsFailed);
            Assert.IsFalse(runner.IsAccessError);
        }
    }
}
