// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Sbom.Api.Tests;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;

namespace Microsoft.Sbom.Api.Hashing.Tests;

[TestClass]
public class HashCodeGeneratorTests
{
    [TestMethod]
    public void GenerateHashTest_Returs2Hashes_Succeeds()
    {
        var hashAlgorithmNames = new
            AlgorithmName[] { AlgorithmName.SHA256, AlgorithmName.SHA512 };
        var expectedHashes = new Checksum[]
        {
            new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "185F8DB32271FE25F561A6FC938B2E264306EC304EDA518007D1764826381969" },
            new Checksum { Algorithm = AlgorithmName.SHA512, ChecksumValue = "3615F80C9D293ED7402687F94B22D58E529B8CC7916F8FAC7FDDF7FBD5AF4CF777D3D795A7A00A16BF7E7F3FB9561EE9BAAE480DA9FE7A18769E71886B03F315" }
        };

        var mockFileSystemUtils = new Mock<IFileSystemUtils>();
        mockFileSystemUtils.Setup(f => f.OpenRead(It.IsAny<string>())).Returns(TestUtils.GenerateStreamFromString("Hello"));

        var hashCodeGenerator = new HashCodeGenerator(mockFileSystemUtils.Object);
        var fileHashes = hashCodeGenerator.GenerateHashes("/tmp/file", hashAlgorithmNames);

        Assert.AreEqual(2, fileHashes.Length);
        CollectionAssert.AreEqual(expectedHashes, fileHashes);
        mockFileSystemUtils.VerifyAll();
    }

    [TestMethod]
    public void GenerateHashTest_FileReadFails_Throws()
    {
        var hashAlgorithmNames = new AlgorithmName[] { AlgorithmName.SHA256, AlgorithmName.SHA512 };
        var expectedHashes = new Checksum[]
        {
            new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = string.Empty },
            new Checksum { Algorithm = AlgorithmName.SHA512, ChecksumValue = string.Empty }
        };

        var mockFileSystemUtils = new Mock<IFileSystemUtils>();
        mockFileSystemUtils.Setup(f => f.OpenRead(It.IsAny<string>())).Throws(new IOException());

        var hashCodeGenerator = new HashCodeGenerator(mockFileSystemUtils.Object);
        Assert.ThrowsException<IOException>(() => hashCodeGenerator.GenerateHashes("/tmp/file", hashAlgorithmNames));
    }

    [TestMethod]
    public void GenerateHashTest_NullFileSystemUtils_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new HashCodeGenerator(null));
    }
}
