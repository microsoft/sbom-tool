// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Moq;
using SbomChecksum = Microsoft.Sbom.Contracts.Checksum;
using SpdxChecksum = Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Checksum;

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

    protected IDictionary<string, SpdxChecksum[]> GetSpdxFilesDictionary() => new Dictionary<string, SpdxChecksum[]>
    {
        ["/child1/file1"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child1/file1hash" } },
        ["/child1/file2"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child1/file2hash" } },
        ["/child2/file3"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/file3hash" } },
        ["/child2/file4"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/file4hash" } },
        ["/child2/file5"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/file5hash" } },
        ["/child3/file11"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child3/file11hash" } },
        ["/child3/file12"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child3/file12hash" } },
        ["/child2/grandchild1/file6"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child2/grandchild1/file6hash" } },
        ["/child5/file8"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "/root/child5/file8hash" } },
        ["/child2/grandchild1/file9"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "incorrectHash" } },
        ["/child2/grandchild2/file10"] = new SpdxChecksum[] { new SpdxChecksum { Algorithm = AlgorithmName.SHA256.Name, ChecksumValue = "missingfile" } }
    };

    protected IDictionary<string, SbomChecksum[]> GetSbomFilesDictionary()
    {
        var spdxDict = GetSpdxFilesDictionary();

        return spdxDict.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.Select(v => new SbomChecksum { Algorithm = AlgorithmName.FromString(v.Algorithm), ChecksumValue = v.ChecksumValue }).ToArray());
    }

    protected ManifestData GetDefaultManifestData() => new()
    {
        HashesMap = new ConcurrentDictionary<string, SbomChecksum[]>(GetSbomFilesDictionary(), StringComparer.InvariantCultureIgnoreCase)
    };

    protected IEnumerable<SPDXFile> GetSpdxFiles(IDictionary<string, SpdxChecksum[]> dictionary) => dictionary
        .Select(file => new SPDXFile
        {
            FileName = $".{file.Key}", // Prepend .
            FileChecksums = file.Value.ToList(),
        });
}
