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

        private const string sourcePath = "/source/path";

        [TestInitialize]
        public void Setup()
        {
            fileSystemUtilsExtension = new FileSystemUtilsExtension()
            {
                FileSystemUtils = fileSystemUtilMock.Object,
                OsUtils = osUtilMock.Object,
            };
            osUtilMock.Setup(o => o.GetFileSystemStringComparisonType()).Returns(System.StringComparison.InvariantCultureIgnoreCase);
            fileSystemUtilMock.Setup(f => f.AbsolutePath(sourcePath)).Returns($"C:{sourcePath}");
        }

        [TestMethod]
        public void When_TargetPathIsOutsideOfSourcePath_Return_False()
        {
            var targetPath = "/source/outsidePath";
            fileSystemUtilMock.Setup(f => f.AbsolutePath(targetPath)).Returns($"C:{targetPath}");

            Assert.IsFalse(fileSystemUtilsExtension.IsTargetPathInSource(targetPath, sourcePath));
        }

        [TestMethod]
        public void When_TargetPathIsInsideOfSourcePath_Return_True()
        {
            var targetPath = "/source/path/insidePath";
            fileSystemUtilMock.Setup(f => f.AbsolutePath(targetPath)).Returns($"C:{targetPath}");

            Assert.IsTrue(fileSystemUtilsExtension.IsTargetPathInSource(targetPath, sourcePath));
        }
    }
}
