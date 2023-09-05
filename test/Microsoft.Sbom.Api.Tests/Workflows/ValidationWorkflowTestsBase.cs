// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Moq;

namespace Microsoft.Sbom.Workflows;

public class ValidationWorkflowTestsBase
{
    protected static Mock<IFileSystemUtils> GetDefaultFileSystemMock()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();
        fileSystemMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "/root"), true)).Returns(new string[] { "child1", "child2", "child3", "_manifest" });
        fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "child1"), true)).Returns(new string[] { });
        fileSystemMock.Setup(f => f.GetDirectories(It.Is<string>(c => c == "child2"), true)).Returns(new string[] { "grandchild1", "grandchild2" });

        // File2 is cased differently than in GetFilesDictionary() to test case insensitivity.
        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child1"), true)).Returns(new string[] { "/root/child1/file1", "/root/child1/File2" });
        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child2"), true)).Returns(new string[] { "/root/child2/file3", "/root/child2/file4", "/root/child2/file5" });
        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "child3"), true)).Returns(new string[] { "/root/child3/file11", "/root/child3/file12" });
        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "_manifest"), true)).Returns(new string[] { "/root/_manifest/manifest.json", "/root/_manifest/manifest.cat" });

        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "grandchild1"), true)).Returns(new string[] { "/root/child2/grandchild1/file6", "/root/child2/grandchild1/file10" });
        fileSystemMock.Setup(f => f.GetFilesInDirectory(It.Is<string>(c => c == "grandchild2"), true)).Returns(new string[] { "/root/child2/grandchild1/file7", "/root/child2/grandchild1/file9" });
        fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string r, string p) => $"{r}/{p}");

        return fileSystemMock;
    }

    protected IDictionary<string, Checksum[]> GetFilesDictionary() => new Dictionary<string, Checksum[]>
    {
        ["/child1/file1"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child1/file1hash" } },
        ["/child1/file2"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child1/file2hash" } },
        ["/child2/file3"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file3hash" } },
        ["/child2/file4"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file4hash" } },
        ["/child2/file5"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/file5hash" } },
        ["/child3/file11"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child3/file11hash" } },
        ["/child3/file12"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child3/file12hash" } },
        ["/child2/grandchild1/file6"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child2/grandchild1/file6hash" } },
        ["/child5/file8"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "/root/child5/file8hash" } },
        ["/child2/grandchild1/file9"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "incorrectHash" } },
        ["/child2/grandchild2/file10"] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = "missingfile" } }
    };

    protected ManifestData GetDefaultManifestData() => new ()
    {
        HashesMap = new ConcurrentDictionary<string, Checksum[]>(GetFilesDictionary(), StringComparer.InvariantCultureIgnoreCase)
    };

    protected IEnumerable<SbomFile> GetSBOMFiles(IDictionary<string, Checksum[]> dictionary) => dictionary
        .Select(file => new SbomFile
        {
            Path = $".{file.Key}", // Prepend .
            Checksum = file.Value
        });
}
