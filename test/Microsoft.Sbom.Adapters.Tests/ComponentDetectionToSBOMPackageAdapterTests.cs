// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.ComponentDetection.Contracts.Internal;

namespace Microsoft.Sbom.Adapters.Tests
{
    [TestClass]
    public class ComponentDetectionToSBOMPackageAdapterTests
    {
        private static TestContext testContext;

        [ClassInitialize]
        public static void SetUp(TestContext testContext)
        {
            ComponentDetectionToSBOMPackageAdapterTests.testContext = testContext;
        }

        [TestMethod]
        public void BasicAdapterTest_Succeeds()
        {
            var json = @"{
                           ""componentsFound"": [
                             {
                                ""locationsFoundAt"": [
                                 ""/Public/Src/Tools/JavaScript/Tool.YarnGraphBuilder/src/package.json""
                               ],
                               ""component"": {
                                 ""name"": ""@microsoft/yarn-graph-builder"",
                                 ""version"": ""1.0.0"",
                                 ""hash"": null,
                                 ""type"": ""Npm"",
                                 ""id"": ""@microsoft/yarn-graph-builder 1.0.0 - Npm"",
                                 ""author"": { 
                                    ""name"": ""some-name""
                                 }
                               },
                               ""detectorId"": ""Npm"",
                               ""isDevelopmentDependency"": null,
                               ""topLevelReferrers"": [],
                               ""containerDetailIds"": []
                             }
                           ],
                           ""detectorsInScan"": [],
                           ""ContainerDetailsMap"": {},
                           ""resultCode"": ""Success""
                         }";
            var (errors, packages) = GenerateJsonFileForTestAndRun(json);

            // Successful conversion
            Assert.IsNotNull(errors.Report);
            Assert.IsTrue(errors.Report?.Count == 1);
            Assert.IsTrue(errors.Report[0].Type == AdapterReportItemType.Success);
            
            // Converted packaged is present and valid
            Assert.IsTrue(packages?.Count == 1);
            Assert.IsNotNull(packages[0]);
            Assert.AreEqual(packages[0].PackageName, "@microsoft/yarn-graph-builder");
            Assert.AreEqual(packages[0].PackageVersion, "1.0.0");
            
            // This one contains no checksums, so verify that it is null
            Assert.IsNotNull(packages[0].Checksum);
            var checksums = packages[0].Checksum?.ToList();
            Assert.IsTrue(checksums?.Count == 1);
            Assert.IsNull(checksums[0].ChecksumValue);
        }

        [TestMethod]
        public void NoComponents_Succeeds()
        {
            var json = @"{
                            ""componentsFound"": [],
                            ""detectorsInScan"": [],
                            ""ContainerDetailsMap"": {},
                            ""resultCode"": ""Success""
                          }";
            var (errors, packages) = GenerateJsonFileForTestAndRun(json);

            Assert.IsTrue(packages?.Count == 0);
            Assert.IsTrue(errors.Report?.Count == 1); // Should still be successful even with no components
            Assert.IsTrue(errors.Report[0].Type == AdapterReportItemType.Success);
        }

        [TestMethod]
        public void MalformedInput_ReturnsError()
        {
            var json = "{";
            var (errors, packages) = GenerateJsonFileForTestAndRun(json);

            Assert.IsTrue(errors.Report?.Count == 1);
            Assert.IsTrue(errors.Report[0].Type == AdapterReportItemType.Failure);
            Assert.IsTrue(errors.Report[0].Details.Contains($"Unable to parse bcde-output.json"));
            Assert.IsTrue(packages.Count == 0);
        }

        [TestMethod]
        public void BadInput_ThrowsException()
        {
            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                ComponentDetectionToSBOMPackageAdapter adapter = new ComponentDetectionToSBOMPackageAdapter();
                adapter.TryConvert("not/a/real/path");
            });
        }

        [TestMethod]
        public void CargoComponent_ToSbomPackage()
        {
            var cargoComponent = new CargoComponent("name", "version");
            var scannedComponent = new ScannedComponent() { Component = cargoComponent }; 

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.IsNotNull(sbomPackage.Id);
            Assert.IsNotNull(sbomPackage.PackageUrl);
            Assert.AreEqual(cargoComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(cargoComponent.Version, sbomPackage.PackageVersion);
        }

        [TestMethod]
        public void CondaComponent_ToSbomPackage()
        {
            var condaComponent = new CondaComponent("name", "version", "build", "channel", "subdir", "namespace", "http://microsoft.com", "md5");
            var scannedComponent = new ScannedComponent() { Component = condaComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(condaComponent.Id, sbomPackage.Id);
            Assert.AreEqual(condaComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(condaComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(condaComponent.Version, sbomPackage.PackageVersion);
            Assert.AreEqual(condaComponent.Url, sbomPackage.PackageSource);
            Assert.AreEqual(condaComponent.MD5, sbomPackage.Checksum.First().ChecksumValue);
        }

        [TestMethod]
        public void DockerImageComponent_ToSbomPackage()
        {
            var dockerImageComponent = new DockerImageComponent("name", "version", "tag") { Digest = "digest" };
            var scannedComponent = new ScannedComponent() { Component = dockerImageComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(dockerImageComponent.Id, sbomPackage.Id);
            Assert.AreEqual(dockerImageComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(dockerImageComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(AlgorithmName.SHA256, sbomPackage.Checksum.First().Algorithm);
            Assert.AreEqual(dockerImageComponent.Digest, sbomPackage.Checksum.First().ChecksumValue);
        }

        [TestMethod]
        public void NpmComponent_ToSbomPackage()
        {
            var npmComponent = new NpmComponent("name", "verison", author: new NpmAuthor("name", "email@contoso.com"));
            var scannedComponent = new ScannedComponent() { Component = npmComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(npmComponent.Id, sbomPackage.Id);
            Assert.AreEqual(npmComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(npmComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(npmComponent.Version, sbomPackage.PackageVersion);
            Assert.AreEqual($"Organization: {npmComponent.Author.Name} ({npmComponent.Author.Email})", sbomPackage.Supplier);
        }

        [TestMethod]
        public void NpmComponent_ToSbomPackage_NoAuthor()
        {
            var npmComponent = new NpmComponent("name", "verison");
            var scannedComponent = new ScannedComponent() { Component = npmComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(npmComponent.Id, sbomPackage.Id);
            Assert.AreEqual(npmComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(npmComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(npmComponent.Version, sbomPackage.PackageVersion);
            Assert.IsNull(sbomPackage.Supplier);
        }

        [TestMethod]
        public void NuGetComponent_ToSbomPackage()
        {
            var nuGetComponent = new NuGetComponent("name", "version", new string[] { "Author Name1, Another Author" });
            var scannedComponent = new ScannedComponent() { Component = nuGetComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(nuGetComponent.Id, sbomPackage.Id);
            Assert.AreEqual(nuGetComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(nuGetComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(nuGetComponent.Version, sbomPackage.PackageVersion);
            Assert.AreEqual($"Organization: {nuGetComponent.Authors.First()}", sbomPackage.Supplier);
        }

        [TestMethod]
        public void NuGetComponent_ToSbomPackage_NoAuthor()
        {
            var nuGetComponent = new NuGetComponent("name", "version");
            var scannedComponent = new ScannedComponent() { Component = nuGetComponent };

            var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport());

            Assert.AreEqual(nuGetComponent.Id, sbomPackage.Id);
            Assert.AreEqual(nuGetComponent.PackageUrl?.ToString(), sbomPackage.PackageUrl);
            Assert.AreEqual(nuGetComponent.Name, sbomPackage.PackageName);
            Assert.AreEqual(nuGetComponent.Version, sbomPackage.PackageVersion);
            Assert.IsNull(sbomPackage.Supplier);
        }

        private (AdapterReport report, List<SBOMPackage> packages) GenerateJsonFileForTestAndRun(string json)
        {
            var baseDirectory = Path.Combine(testContext.TestRunDirectory, Guid.NewGuid().ToString());
            var bcdeOutputPath = Path.Combine(baseDirectory, "bcde-output.json");

            Directory.CreateDirectory(baseDirectory);
            File.WriteAllText(bcdeOutputPath, json);

            ComponentDetectionToSBOMPackageAdapter adapter = new ComponentDetectionToSBOMPackageAdapter();
            var (errors, packages) = adapter.TryConvert(bcdeOutputPath);
            var output = packages.ToList();

            // Clean up generated directories/files
            File.Delete(bcdeOutputPath);
            Directory.Delete(baseDirectory);

            // Unless the TryConvert call throws an exception, these should never be null
            Assert.IsNotNull(packages);
            Assert.IsNotNull(errors);

            return (errors, output);
        }
    }
}
