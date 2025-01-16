// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class FileListEnumeratorTests
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();

    [TestMethod]
    public async Task ListWalkerTests_ValidListFile_SucceedsAsync()
    {
        var files = new List<string>
        {
            @"d:\directorya\directoryb\file1.txt",
            @"d:\directorya\directoryc\file3.txt",
        };

        var fileText = string.Join(Environment.NewLine, files);
        var testFileName = "somefile";

        var mockFSUtils = new Mock<IFileSystemUtils>();
        mockFSUtils.Setup(m => m.ReadAllText(It.Is<string>(d => d == testFileName))).Returns(fileText).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == testFileName))).Returns(true).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[0]))).Returns(true).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[1]))).Returns(true).Verifiable();
        mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[0]))).Returns(files[0]);
        mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[1]))).Returns(files[1]);

        var filesChannelReader = new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(testFileName);
        var errorCount = 0;

        await foreach (var error in filesChannelReader.errors.ReadAllAsync())
        {
            Assert.AreEqual(Entities.ErrorType.MissingFile, error.ErrorType);
            errorCount++;
        }

        await foreach (var file in filesChannelReader.file.ReadAllAsync())
        {
            Assert.IsTrue(files.Remove(file));
        }

        Assert.AreEqual(0, errorCount);
        Assert.AreEqual(0, files.Count);
        mockFSUtils.VerifyAll();
    }

    [TestMethod]
    public void ListWalkerTests_ListFile_Null_Fails()
    {
        var mockFSUtils = new Mock<IFileSystemUtils>();
        Assert.ThrowsException<ArgumentException>(() =>
            new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(null));
        mockFSUtils.VerifyAll();
    }

    [TestMethod]
    public void ListWalkerTests_DirectoryDoesntExist_Fails()
    {
        var mockFSUtils = new Mock<IFileSystemUtils>();
        Assert.ThrowsException<InvalidPathException>(() =>
            new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(@"BadDir"));
        mockFSUtils.VerifyAll();
    }

    [TestMethod]
    public async Task ListWalkerTests_UnreachableFile_FailsAsync()
    {
        var files = new List<string>
        {
            @"d:\directorya\directoryb\file1.txt",
            @"d:\directorya\directoryc\file3.txt",
        };

        var fileText = string.Join(Environment.NewLine, files);
        var testFileName = "somefile";

        var mockFSUtils = new Mock<IFileSystemUtils>();
        mockFSUtils.Setup(m => m.ReadAllText(It.Is<string>(d => d == testFileName))).Returns(fileText).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == testFileName))).Returns(true).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[0]))).Returns(true).Verifiable();
        mockFSUtils.Setup(m => m.FileExists(It.Is<string>(d => d == files[1]))).Returns(false).Verifiable();
        mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[0]))).Returns(files[0]);
        mockFSUtils.Setup(m => m.AbsolutePath(It.Is<string>(d => d == files[1]))).Returns(files[1]);

        var filesChannelReader = new FileListEnumerator(mockFSUtils.Object, mockLogger.Object).GetFilesFromList(testFileName);
        var errorCount = 0;

        await foreach (var error in filesChannelReader.errors.ReadAllAsync())
        {
            Assert.AreEqual(Entities.ErrorType.MissingFile, error.ErrorType);
            errorCount++;
        }

        await foreach (var file in filesChannelReader.file.ReadAllAsync())
        {
            Assert.IsTrue(files.Remove(file));
        }

        Assert.AreEqual(1, errorCount);
        Assert.AreEqual(1, files.Count);
        mockFSUtils.VerifyAll();
    }
}
