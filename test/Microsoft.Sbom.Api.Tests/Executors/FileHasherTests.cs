// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class FileHasherTests
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IConfiguration> mockConfiguration = new Mock<IConfiguration>();

    private readonly ConcurrentDictionary<string, Checksum[]> hashDict = new ConcurrentDictionary<string, Checksum[]>();
    private HashSet<string> fileList = new HashSet<string>();

    [TestInitialize]
    public void TestInitialize()
    {
        fileList = new HashSet<string>()
        {
            "test1",
            "test2",
            "test3"
        };
        foreach (var file in fileList)
        {
            hashDict[file] = new Checksum[]
            {
                new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hash" }
            };
        }

        ManifestDataSingleton.ResetDictionary();
    }

    [TestMethod]
    public async Task FileHasherTest_Validate_MultipleFiles_SucceedsAsync()
    {
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        var manifestPathConverter = new Mock<IManifestPathConverter>();

        mockConfiguration.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        mockConfiguration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        hashCodeGeneratorMock.Setup(m => m.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns(new Checksum[]
            {
                new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = "hash" }
            });
        manifestPathConverter.Setup(m => m.Convert(It.IsAny<string>(), false)).Returns((string r, bool v) => (r, true));

        var files = Channel.CreateUnbounded<string>();
        (ChannelReader<InternalSbomFileInfo> file, ChannelReader<FileValidationResult> error) fileHashes
            = new FileHasher(
                    hashCodeGeneratorMock.Object,
                    manifestPathConverter.Object,
                    mockLogger.Object,
                    mockConfiguration.Object,
                    new Mock<ISbomConfigProvider>().Object,
                    new ManifestGeneratorProvider(null),
                    new FileTypeUtils())
                .Run(files);
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(file);
        }

        files.Writer.Complete();

        await foreach (var fileHash in fileHashes.file.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(fileHash.Path));
            Assert.AreEqual("hash", fileHash.Checksum.First().ChecksumValue);
            Assert.IsNull(fileHash.FileTypes);
        }

        Assert.AreEqual(0, fileHashes.error.Count);
        hashCodeGeneratorMock.VerifyAll();
        manifestPathConverter.VerifyAll();
        mockConfiguration.VerifyAll();
    }

    [TestMethod]
    public async Task FileHasherTest_Validate_ManifestPathConverterThrows_ReturnsValidationFailureAsync()
    {
        mockConfiguration.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        mockConfiguration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        var manifestPathConverter = new Mock<IManifestPathConverter>();

        hashCodeGeneratorMock.Setup(m => m.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns(new Checksum[]
            {
                new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = "hash" }
            });

        manifestPathConverter.Setup(m => m.Convert(It.IsAny<string>(), false)).Returns((string r, bool v) => (r, true));
        manifestPathConverter.Setup(m => m.Convert(It.Is<string>(d => d == "test2"), false)).Throws(new InvalidPathException());

        var fileHasher = new FileHasher(
            hashCodeGeneratorMock.Object,
            manifestPathConverter.Object,
            mockLogger.Object,
            mockConfiguration.Object,
            new Mock<ISbomConfigProvider>().Object,
            new ManifestGeneratorProvider(null),
            new FileTypeUtils())
        {
            ManifestData = ManifestDataSingleton.Instance
        };

        var files = Channel.CreateUnbounded<string>();
        (ChannelReader<InternalSbomFileInfo> file, ChannelReader<FileValidationResult> error) fileHashes
            = fileHasher.Run(files);
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(file);
        }

        files.Writer.Complete();
        var errorCount = 0;
        var filesCount = 0;

        await foreach (var fileHash in fileHashes.file.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(fileHash.Path));
            Assert.AreEqual("hash", fileHash.Checksum.First().ChecksumValue);
            Assert.IsNull(fileHash.FileTypes);
            filesCount++;
        }

        await foreach (var error in fileHashes.error.ReadAllAsync())
        {
            Assert.AreEqual(Entities.ErrorType.Other, error.ErrorType);
            errorCount++;
        }

        Assert.AreEqual(3, ManifestDataSingleton.Instance.HashesMap.Count);
        Assert.AreEqual(2, filesCount);
        Assert.AreEqual(1, errorCount);
        hashCodeGeneratorMock.VerifyAll();
        hashCodeGeneratorMock.Verify(h => h.GenerateHashes(It.IsAny<string>(), It.IsAny<AlgorithmName[]>()), Times.Exactly(2));
        manifestPathConverter.VerifyAll();
        mockConfiguration.VerifyAll();
    }

    [TestMethod]
    public async Task FileHasherTest_Validate_HashError_ReturnsValidationFailureAsync()
    {
        mockConfiguration.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Validate);
        mockConfiguration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        var manifestPathConverter = new Mock<IManifestPathConverter>();

        hashCodeGeneratorMock.SetupSequence(m => m.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns(new Checksum[]
            {
                new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = "hash" }
            })
            .Returns(new Checksum[]
            {
                new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = string.Empty }
            })
            .Throws(new UnauthorizedAccessException("Can't access file"));
        manifestPathConverter.Setup(m => m.Convert(It.IsAny<string>(), false)).Returns((string r, bool v) => (r, true));

        var fileHasher = new FileHasher(
            hashCodeGeneratorMock.Object,
            manifestPathConverter.Object,
            mockLogger.Object,
            mockConfiguration.Object,
            new Mock<ISbomConfigProvider>().Object,
            new ManifestGeneratorProvider(null),
            new FileTypeUtils())
        {
            ManifestData = ManifestDataSingleton.Instance
        };

        var files = Channel.CreateUnbounded<string>();
        (ChannelReader<InternalSbomFileInfo> file, ChannelReader<FileValidationResult> error) fileHashes
            = fileHasher.Run(files);
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(file);
        }

        files.Writer.Complete();
        var errorCount = 0;
        var filesCount = 0;

        await foreach (var fileHash in fileHashes.file.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(fileHash.Path));
            Assert.AreEqual("hash", fileHash.Checksum.First().ChecksumValue);
            Assert.IsNull(fileHash.FileTypes);
            filesCount++;
        }

        await foreach (var error in fileHashes.error.ReadAllAsync())
        {
            Assert.AreEqual(Entities.ErrorType.Other, error.ErrorType);
            errorCount++;
        }

        Assert.AreEqual(1, ManifestDataSingleton.Instance.HashesMap.Count);
        Assert.AreEqual(1, filesCount);
        Assert.AreEqual(2, errorCount);
        hashCodeGeneratorMock.VerifyAll();
        manifestPathConverter.VerifyAll();
        mockConfiguration.VerifyAll();
    }

    [TestMethod]
    public async Task FileHasherTest_Generate_MultipleFiles_SucceedsAsync()
    {
        var hashCodeGeneratorMock = new Mock<IHashCodeGenerator>();
        var manifestPathConverter = new Mock<IManifestPathConverter>();

        mockConfiguration.SetupGet(c => c.ManifestToolAction).Returns(ManifestToolActions.Generate);

        hashCodeGeneratorMock.Setup(m => m.GenerateHashes(
                It.IsAny<string>(),
                new AlgorithmName[] { Constants.DefaultHashAlgorithmName }))
            .Returns(new Checksum[]
            {
                new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = "hash" }
            });

        var manifestInfoList = new List<ManifestInfo>
        {
            ManifestInfo.Parse("test:1"),
            ManifestInfo.Parse("test:2")
        };

        var generator1 = new Mock<IManifestGenerator>();
        var generator2 = new Mock<IManifestGenerator>();

        generator1.Setup(g => g.RegisterManifest()).Returns(ManifestInfo.Parse("test:1"));
        generator2.Setup(g => g.RequiredHashAlgorithms).Returns(new AlgorithmName[] { AlgorithmName.SHA256 });
        generator2.Setup(g => g.RegisterManifest()).Returns(ManifestInfo.Parse("test:2"));

        var manifestGenProvider = new ManifestGeneratorProvider(new IManifestGenerator[]
        {
            generator1.Object,
            generator2.Object
        });

        manifestGenProvider.Init();

        var sbomConfigs = new Mock<ISbomConfigProvider>();
        sbomConfigs.Setup(s => s.GetManifestInfos()).Returns(manifestInfoList);

        manifestPathConverter.Setup(m => m.Convert(It.IsAny<string>(), It.IsAny<bool>())).Returns((string r, bool v) => (r, true));

        var files = Channel.CreateUnbounded<string>();
        (ChannelReader<InternalSbomFileInfo> file, ChannelReader<FileValidationResult> error) fileHashes
            = new FileHasher(
                    hashCodeGeneratorMock.Object,
                    manifestPathConverter.Object,
                    mockLogger.Object,
                    mockConfiguration.Object,
                    sbomConfigs.Object,
                    manifestGenProvider,
                    new FileTypeUtils())
                .Run(files);
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(file);
        }

        files.Writer.Complete();

        await foreach (var fileHash in fileHashes.file.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(fileHash.Path));
            Assert.AreEqual("hash", fileHash.Checksum.First().ChecksumValue);
            Assert.IsNull(fileHash.FileTypes);
        }

        Assert.AreEqual(0, fileHashes.error.Count);
        hashCodeGeneratorMock.VerifyAll();
        manifestPathConverter.VerifyAll();
        mockConfiguration.VerifyAll();
    }

    private sealed class ManifestDataSingleton
    {
        private static readonly IDictionary<string, Checksum[]> HashDictionary = new Dictionary<string, Checksum[]>
        {
            ["test1"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "test1_hash" } },
            ["test2"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "test2_hash" } },
            ["test3"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "test3_hash" } },
        };

        private static readonly Lazy<ManifestData>
            Lazy =
                new Lazy<ManifestData>(
                    () => new ManifestData { HashesMap = new ConcurrentDictionary<string, Checksum[]>(HashDictionary, StringComparer.InvariantCultureIgnoreCase) });

        public static ManifestData Instance { get { return Lazy.Value; } }

        private ManifestDataSingleton() { }

        public static void ResetDictionary()
        {
            Lazy.Value.HashesMap = new ConcurrentDictionary<string, Checksum[]>(HashDictionary, StringComparer.InvariantCultureIgnoreCase);
        }
    }
}
