using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Executors.Tests
{
    [TestClass]
    public class FileListEnumeratorTests
    {
        private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();

        [TestMethod]
        public async Task ListWalkerTests_ValidListFile_SucceedsAsync()
        {
            List<string> files = new List<string>
            {
                @"d:\directorya\directoryb\file1.txt",
                @"d:\directorya\directoryc\file3.txt",
            };

            string fileText = string.Join(Environment.NewLine, files);
            string testFileName = "somefile";

            var mockFSUtils = new Mock<IFileSystemUtils>();
            mockFSUtils.Setup(m => m.ReadAllText(It.Is<string>(d => d == testFileName))).Returns(fileText).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == testFileName))).Returns(true).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[0]))).Returns(true).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[1]))).Returns(true).Verifiable();
            mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[0]))).Returns(files[0]);
            mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[1]))).Returns(files[1]);

            var filesChannelReader = new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(testFileName);
            int errorCount = 0;

            await foreach (Entities.FileValidationResult error in filesChannelReader.errors.ReadAllAsync())
            {
                Assert.AreEqual(Entities.ErrorType.MissingFile, error.ErrorType);
                errorCount++;
            }

            await foreach (string file in filesChannelReader.file.ReadAllAsync())
            {
                Assert.IsTrue(files.Remove(file));
            }

            Assert.IsTrue(errorCount == 0);
            Assert.IsTrue(files.Count == 0);
            mockFSUtils.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ListWalkerTests_ListFile_Null_Fails()
        {
            var mockFSUtils = new Mock<IFileSystemUtils>();
            mockFSUtils.Setup(m => m.DirectoryExists(It.IsAny<string>())).Returns(false).Verifiable();
            new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(null);
            mockFSUtils.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidPathException))]
        public void ListWalkerTests_DirectoryDoesntExist_Fails()
        {
            var mockFSUtils = new Mock<IFileSystemUtils>();
            mockFSUtils.Setup(m => m.DirectoryExists(It.IsAny<string>())).Returns(false).Verifiable();
            new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(@"BadDir");
            mockFSUtils.VerifyAll();
        }

        [TestMethod]
        public async Task ListWalkerTests_UnreachableFile_FailsAsync()
        {
            List<string> files = new List<string>
            { 
                @"d:\directorya\directoryb\file1.txt",
                @"d:\directorya\directoryc\file3.txt",
            };

            string fileText = string.Join(Environment.NewLine, files);
            string testFileName = "somefile";

            var mockFSUtils = new Mock<IFileSystemUtils>();
            mockFSUtils.Setup(m => m.ReadAllText(It.Is<string>(d => d == testFileName))).Returns(fileText).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == testFileName))).Returns(true).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[0]))).Returns(true).Verifiable();
            mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[1]))).Returns(false).Verifiable();
            mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[0]))).Returns(files[0]);
            mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[1]))).Returns(files[1]);

            var filesChannelReader = new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(testFileName);
            int errorCount = 0;

            await foreach (Entities.FileValidationResult error in filesChannelReader.errors.ReadAllAsync())
            {
                Assert.AreEqual(Entities.ErrorType.MissingFile, error.ErrorType);
                errorCount++;
            }

            await foreach (string file in filesChannelReader.file.ReadAllAsync())
            {
                Assert.IsTrue(files.Remove(file));
            }

            Assert.IsTrue(errorCount == 1);
            Assert.IsTrue(files.Count == 1);
            mockFSUtils.VerifyAll();
        }
    }
}