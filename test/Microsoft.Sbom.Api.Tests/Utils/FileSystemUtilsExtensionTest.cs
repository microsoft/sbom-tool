// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class FileSystemUtilsExtensionTest
    {
        private readonly Mock<IFileSystemUtils> fileSystemUtilMock = new Mock<IFileSystemUtils>();
        private readonly Mock<IOSUtils> osUtilMock = new Mock<IOSUtils>();
        private FileSystemUtilsExtension fileSystemUtilsExtension;

        private const string SourcePath = "/source/path";

        [TestInitialize]
        public void Setup()
        {
            fileSystemUtilsExtension = new FileSystemUtilsExtension()
            {
                FileSystemUtils = fileSystemUtilMock.Object,
                OsUtils = osUtilMock.Object,
            };
            osUtilMock.Setup(o => o.GetFileSystemStringComparisonType()).Returns(System.StringComparison.InvariantCultureIgnoreCase);
            fileSystemUtilMock.Setup(f => f.AbsolutePath(SourcePath)).Returns($"C:{SourcePath}");
        }

        [TestMethod]
        public void When_TargetPathIsOutsideOfSourcePath_Return_False()
        {
            var targetPath = "/source/outsidePath";
            fileSystemUtilMock.Setup(f => f.AbsolutePath(targetPath)).Returns($"C:{targetPath}");

            Assert.IsFalse(fileSystemUtilsExtension.IsTargetPathInSource(targetPath, SourcePath));
        }

        [TestMethod]
        public void When_TargetPathIsInsideOfSourcePath_Return_True()
        {
            var targetPath = "/source/path/insidePath";
            fileSystemUtilMock.Setup(f => f.AbsolutePath(targetPath)).Returns($"C:{targetPath}");

            Assert.IsTrue(fileSystemUtilsExtension.IsTargetPathInSource(targetPath, SourcePath));
        }
    }
}
