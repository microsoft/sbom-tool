// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests.Utility;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

/// <summary>
/// This class is used to validate that the generated SBOM has valid fields and data.
/// </summary>
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
internal class GeneratedSbomValidator
{
    private readonly SbomSpecification sbomSpecification;

    public GeneratedSbomValidator(SbomSpecification sbomSpecification)
    {
        this.sbomSpecification = sbomSpecification;
    }

    internal void AssertSbomIsValid(string manifestPath, string buildDropPath, string expectedPackageName, string expectedPackageVersion, string expectedPackageSupplier, string expectedNamespaceUriBase, string expectedNamespaceUriUniquePart = null, string buildComponentPath = null)
    {
        Assert.IsTrue(File.Exists(manifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(manifestPath);
        var manifest = JsonConvert.DeserializeObject<dynamic>(manifestContent);

        if (this.sbomSpecification.Equals(Constants.SPDX22Specification))
        {
            // Check the manifest has expected file data
            var filesValue = manifest["files"];
            Assert.IsNotNull(filesValue);

            var expectedFilesHashes = this.GetBuildDropFileHashes(buildDropPath);
            Assert.AreEqual(expectedFilesHashes.Count, filesValue.Count);
            foreach (var file in filesValue)
            {
                var filePath = Path.GetFullPath(Path.Combine(buildDropPath, (string)file["fileName"]));
                var fileChecksums = file["checksums"];
                Assert.IsNotNull(fileChecksums);

                foreach (var checksum in fileChecksums)
                {
                    var algorithm = (string)checksum["algorithm"];
                    var hash = (string)checksum["checksumValue"];
                    Assert.IsNotNull(algorithm);
                    Assert.IsNotNull(hash);

                    Assert.IsTrue(expectedFilesHashes.ContainsKey(filePath));
                    Assert.IsTrue(expectedFilesHashes[filePath].ContainsKey(algorithm));
                    Assert.IsTrue(expectedFilesHashes[filePath][algorithm].Equals(hash, StringComparison.InvariantCultureIgnoreCase));
                }
            }

            var packagesValue = manifest["packages"];
            Assert.IsNotNull(packagesValue);
            if (string.IsNullOrEmpty(buildComponentPath))
            {
                Assert.IsTrue(packagesValue.Count == 1);
            }
            else
            {
                Assert.IsTrue(packagesValue.Count > 1);
            }

            var nameValue = manifest["name"];
            Assert.IsNotNull(nameValue);
            Assert.AreEqual($"{expectedPackageName} {expectedPackageVersion}", (string)nameValue);

            var creatorsValue = manifest["creationInfo"]["creators"];
            Assert.IsNotNull(creatorsValue);
            Assert.IsTrue(creatorsValue.Count > 0);
            Assert.IsTrue(((string)creatorsValue[0]).Contains(expectedPackageSupplier));

            string namespaceValue = manifest["documentNamespace"];
            Assert.IsNotNull(namespaceValue);

            if (expectedNamespaceUriUniquePart != null)
            {
                Assert.IsTrue(namespaceValue.Equals($"{expectedNamespaceUriBase.Trim()}/{expectedPackageName}/{expectedPackageVersion}/{expectedNamespaceUriUniquePart.Trim()}", StringComparison.InvariantCultureIgnoreCase));
            }
            else
            {
                Assert.IsTrue(namespaceValue.Contains($"{expectedNamespaceUriBase.Trim()}/{expectedPackageName}/{expectedPackageVersion}", StringComparison.InvariantCultureIgnoreCase));
            }
        }
    }

    private IDictionary<string, IDictionary<string, string>> GetBuildDropFileHashes(string buildDropPath)
    {
        var filesHashes = new Dictionary<string, IDictionary<string, string>>();

        // Get all files in the buildDropPath and its subfolders
        var files = Directory.GetFiles(buildDropPath, "*", SearchOption.AllDirectories)
            .Where(f => !f.Contains("manifest.spdx.json"))
            .Select(Path.GetFullPath);

        // Compute hashes for each file.
        foreach (var filePath in files)
        {
            var fileHashes = new Dictionary<string, string>();
            // Compute hashes for the file.
            foreach (var hashAlgorithmPair in this.GetListOfHashAlgorithmCreators())
            {
                using var stream = File.OpenRead(filePath);
                using var hashAlgorithmInstance = hashAlgorithmPair.Item2();
                var hash = hashAlgorithmInstance.ComputeHash(stream);
                var hashString = BitConverter.ToString(hash).Replace("-", string.Empty);
                fileHashes.Add(hashAlgorithmPair.Item1, hashString);
            }

            filesHashes.Add(filePath, fileHashes);
        }

        return filesHashes;
    }

    private IList<(string, Func<HashAlgorithm>)> GetListOfHashAlgorithmCreators()
    {
        if (this.sbomSpecification.Equals(Constants.SPDX22Specification))
        {
            return [("SHA1", SHA1.Create), ("SHA256", SHA256.Create)];
        }

        return [];
    }
}
