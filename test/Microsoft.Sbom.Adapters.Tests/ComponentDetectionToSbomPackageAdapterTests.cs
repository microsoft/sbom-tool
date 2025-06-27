// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.ComponentDetection.Contracts.Internal;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Adapters.Tests;

using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.Sbom.Common;
using Moq;

[TestClass]
public class ComponentDetectionToSBOMPackageAdapterTests
{
    private Mock<IOSUtils> osUtils;

    public TestContext TestContext { get; set; }

    [TestInitialize]
    public void Setup()
    {
        this.osUtils = new Mock<IOSUtils>();
    }

    [TestMethod]
    public void BasicAdapterTest_Succeeds()
    {
#pragma warning disable JSON002 // Probable JSON string detected
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
#pragma warning restore JSON002 // Probable JSON string detected
        var (errors, packages) = GenerateJsonFileForTestAndRun(json);

        // Successful conversion
        Assert.AreEqual(1, errors.Report.Count);
        Assert.AreEqual(AdapterReportItemType.Success, errors.Report.First().Type);

        // Converted packaged is present and valid
        Assert.IsNotNull(packages);
        Assert.AreEqual(1, packages.Count);
        Assert.IsNotNull(packages[0]);
        Assert.AreEqual("@microsoft/yarn-graph-builder", packages[0].PackageName);
        Assert.AreEqual("1.0.0", packages[0].PackageVersion);

        // This one contains no checksums, so verify that it is null
        Assert.IsNotNull(packages[0].Checksum);
        var checksums = packages[0].Checksum?.ToList();
        Assert.IsNotNull(checksums);
        Assert.AreEqual(1, checksums.Count);
        Assert.IsNull(checksums[0].ChecksumValue);
    }

    [TestMethod]
    public void NoComponents_Succeeds()
    {
#pragma warning disable JSON002 // Probable JSON string detected
        var json = @"{
                            ""componentsFound"": [],
                            ""detectorsInScan"": [],
                            ""ContainerDetailsMap"": {},
                            ""resultCode"": ""Success""
                          }";
#pragma warning restore JSON002 // Probable JSON string detected
        var (errors, packages) = GenerateJsonFileForTestAndRun(json);

        Assert.IsNotNull(packages);
        Assert.AreEqual(0, packages.Count);
        Assert.AreEqual(1, errors.Report.Count); // Should still be successful even with no components
        Assert.AreEqual(AdapterReportItemType.Success, errors.Report.First().Type);
    }

    [TestMethod]
    public void MalformedInput_ReturnsError()
    {
        var json = "{";
        var (errors, packages) = GenerateJsonFileForTestAndRun(json);

        Assert.AreEqual(1, errors.Report.Count);
        Assert.AreEqual(AdapterReportItemType.Failure, errors.Report.First().Type);
        Assert.IsTrue(errors.Report.First().Details.Contains("Unable to parse bcde-output.json", StringComparison.Ordinal));
        Assert.AreEqual(0, packages.Count);
    }

    [TestMethod]
    public void BadInput_ThrowsException()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            var adapter = new ComponentDetectionToSbomPackageAdapter(this.osUtils.Object);
            adapter.TryConvert("not/a/real/path");
        });
    }

    [TestMethod]
    public void CargoComponent_ToSbomPackage()
    {
        var cargoComponent = new CargoComponent("name", "version");
        var scannedComponent = new ExtendedScannedComponent() { Component = cargoComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.IsNotNull(sbomPackage.Id);
        Assert.IsNotNull(sbomPackage.PackageUrl);
        Assert.AreEqual(cargoComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(cargoComponent.Version, sbomPackage.PackageVersion);
    }

    [TestMethod]
    public void ConanComponent_ToSbomPackage()
    {
        var md5 = Guid.NewGuid().ToString();
        var sha1Hash = Guid.NewGuid().ToString();

        var conanComponent = new ConanComponent("name", "version", md5, sha1Hash);
        var scannedComponent = new ExtendedScannedComponent() { Component = conanComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.IsNotNull(sbomPackage.Id);
        Assert.IsNotNull(sbomPackage.PackageUrl);
        Assert.AreEqual(conanComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(conanComponent.Version, sbomPackage.PackageVersion);
        Assert.IsNotNull(sbomPackage.Checksum.First(x => x.ChecksumValue == conanComponent.Md5Hash));
        Assert.IsNotNull(sbomPackage.Checksum.First(x => x.ChecksumValue == conanComponent.Sha1Hash));
        Assert.AreEqual(conanComponent.PackageSourceURL, sbomPackage.PackageSource);
    }

    [TestMethod]
    public void CondaComponent_ToSbomPackage()
    {
        var condaComponent = new CondaComponent("name", "version", "build", "channel", "subdir", "namespace", "http://microsoft.com", "md5");
        var scannedComponent = new ExtendedScannedComponent() { Component = condaComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(condaComponent.Id, sbomPackage.Id);
        AssertPackageUrlIsCorrect(condaComponent.PackageUrl, sbomPackage.PackageUrl);
        Assert.AreEqual(condaComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(condaComponent.Version, sbomPackage.PackageVersion);
        Assert.AreEqual(condaComponent.Url, sbomPackage.PackageSource);
        Assert.AreEqual(condaComponent.MD5, sbomPackage.Checksum.First().ChecksumValue);
    }

    [TestMethod]
    public void DockerImageComponent_ToSbomPackage()
    {
        var dockerImageComponent = new DockerImageComponent("name", "version", "tag") { Digest = "digest" };
        var scannedComponent = new ExtendedScannedComponent() { Component = dockerImageComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(dockerImageComponent.Id, sbomPackage.Id);
        AssertPackageUrlIsCorrect(dockerImageComponent.PackageUrl, sbomPackage.PackageUrl);
        Assert.AreEqual(dockerImageComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(AlgorithmName.SHA256, sbomPackage.Checksum.First().Algorithm);
        Assert.AreEqual(dockerImageComponent.Digest, sbomPackage.Checksum.First().ChecksumValue);
    }

    [TestMethod]
    public void NpmComponent_ToSbomPackage()
    {
        var npmComponent = new NpmComponent("name", "verison", author: new NpmAuthor("name", "email@contoso.com"));
        var scannedComponent = new ExtendedScannedComponent() { Component = npmComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(npmComponent.Id, sbomPackage.Id);
        Assert.IsNotNull(npmComponent.PackageUrl);
        Assert.AreEqual(npmComponent.PackageUrl.ToString(), sbomPackage.PackageUrl);
        Assert.AreEqual(npmComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(npmComponent.Version, sbomPackage.PackageVersion);
        Assert.AreEqual($"Organization: {npmComponent.Author.Name} ({npmComponent.Author.Email})", sbomPackage.Supplier);
    }

    [TestMethod]
    public void NpmComponent_ToSbomPackage_NoAuthor()
    {
        var npmComponent = new NpmComponent("name", "verison");
        var scannedComponent = new ExtendedScannedComponent() { Component = npmComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(npmComponent.Id, sbomPackage.Id);
        Assert.IsNotNull(npmComponent.PackageUrl);
        Assert.AreEqual(npmComponent.PackageUrl.ToString(), sbomPackage.PackageUrl);
        Assert.AreEqual(npmComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(npmComponent.Version, sbomPackage.PackageVersion);
        Assert.IsNull(sbomPackage.Supplier);
    }

    [TestMethod]
    public void NuGetComponent_ToSbomPackage()
    {
        var nuGetComponent = new NuGetComponent("name", "version", new string[] { "Author Name1, Another Author" });
        var scannedComponent = new ExtendedScannedComponent() { Component = nuGetComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(nuGetComponent.Id, sbomPackage.Id);
        AssertPackageUrlIsCorrect(nuGetComponent.PackageUrl, sbomPackage.PackageUrl);
        Assert.AreEqual(nuGetComponent.PackageUrl.ToString(), sbomPackage.PackageUrl);
        Assert.AreEqual(nuGetComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(nuGetComponent.Version, sbomPackage.PackageVersion);
        Assert.AreEqual($"Organization: {nuGetComponent.Authors.First()}", sbomPackage.Supplier);
    }

    [TestMethod]
    public void NuGetComponent_ToSbomPackage_NoAuthor()
    {
        var nuGetComponent = new NuGetComponent("name", "version");
        var scannedComponent = new ExtendedScannedComponent() { Component = nuGetComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(nuGetComponent.Id, sbomPackage.Id);
        Assert.IsNotNull(nuGetComponent.PackageUrl);
        Assert.AreEqual(nuGetComponent.PackageUrl.ToString(), sbomPackage.PackageUrl);
        Assert.AreEqual(nuGetComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(nuGetComponent.Version, sbomPackage.PackageVersion);
        Assert.IsNull(sbomPackage.Supplier);
    }

    [TestMethod]
    public void PipComponent_ToSbomPackage()
    {
        var pipComponent = new PipComponent("name", "version");
        var scannedComponent = new ExtendedScannedComponent() { Component = pipComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(pipComponent.Id, sbomPackage.Id);
        Assert.IsNotNull(pipComponent.PackageUrl);
        Assert.AreEqual(pipComponent.PackageUrl.ToString(), sbomPackage.PackageUrl);
        Assert.AreEqual(pipComponent.Name, sbomPackage.PackageName);
        Assert.AreEqual(pipComponent.Version, sbomPackage.PackageVersion);
    }

    [TestMethod]
    public void GitComponent_ToSbomPackage()
    {
        var uri = new Uri("https://microsoft.com");
        var gitComponent = new GitComponent(uri, "version");
        var scannedComponent = new ExtendedScannedComponent() { Component = gitComponent };

        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(gitComponent.Id, sbomPackage.Id);
        AssertPackageUrlIsCorrect(gitComponent.PackageUrl, sbomPackage.PackageUrl);
    }

    [TestMethod]
    public void DotNetComponent_ToSbomPackage()
    {
        this.osUtils.Setup(x => x.GetEnvironmentVariable("EnableSBOM_DotNetComponent")).Returns("true");

        var dotnetComponent = new DotNetComponent("6.0.102", "net6.0", "application");
        var scannedComponent = new ExtendedScannedComponent() { Component = dotnetComponent };
        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(dotnetComponent.Id, sbomPackage.Id);
        Assert.AreEqual(dotnetComponent.SdkVersion, sbomPackage.PackageVersion);
        Assert.IsNotNull(sbomPackage.PackageName);

        var nameSegments = sbomPackage.PackageName.Split(' ');
        Assert.AreEqual(2, nameSegments.Length);

        Assert.AreEqual(dotnetComponent.TargetFramework, nameSegments[0], $"{nameof(dotnetComponent.TargetFramework)} should be part of package name");
        Assert.AreEqual(dotnetComponent.ProjectType, nameSegments[1], $"{nameof(dotnetComponent.ProjectType)} should be part of package name");

        dotnetComponent = new DotNetComponent("6.0.102", "net6.0");
        scannedComponent = new ExtendedScannedComponent() { Component = dotnetComponent };
        sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(dotnetComponent.Id, sbomPackage.Id);
        Assert.AreEqual(dotnetComponent.SdkVersion, sbomPackage.PackageVersion);
        Assert.IsNotNull(sbomPackage.PackageName);

        nameSegments = sbomPackage.PackageName.Split(' ');
        Assert.AreEqual(1, nameSegments.Length);

        Assert.AreEqual(dotnetComponent.TargetFramework, nameSegments[0], $"{nameof(dotnetComponent.TargetFramework)} should be part of package name");

        dotnetComponent = new DotNetComponent("6.0.102");
        scannedComponent = new ExtendedScannedComponent() { Component = dotnetComponent };
        sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(dotnetComponent.Id, sbomPackage.Id);
        Assert.IsNotNull(sbomPackage.PackageName);
        Assert.AreEqual(dotnetComponent.SdkVersion, sbomPackage.PackageVersion);
        Assert.AreEqual(dotnetComponent.SdkVersion, sbomPackage.PackageName);

        dotnetComponent = new DotNetComponent(sdkVersion: null, targetFramework: "net6.0");
        scannedComponent = new ExtendedScannedComponent() { Component = dotnetComponent };
        sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);

        Assert.AreEqual(dotnetComponent.Id, sbomPackage.Id);
        Assert.IsNull(sbomPackage.PackageVersion);
        Assert.IsNotNull(sbomPackage.PackageName);

        nameSegments = sbomPackage.PackageName.Split(' ');
        Assert.AreEqual(1, nameSegments.Length);
        Assert.AreEqual(dotnetComponent.TargetFramework, nameSegments[0], $"{nameof(dotnetComponent.TargetFramework)} should be part of package name");
    }

    [TestMethod]
    public void DotNetComponentDisabled_ToSbomPackage()
    {
        this.osUtils.Setup(x => x.GetEnvironmentVariable("EnableSBOM_DotNetComponent")).Returns("false");

        var dotnetComponent = new DotNetComponent("6.0.102", "net6.0", "application");
        var scannedComponent = new ExtendedScannedComponent() { Component = dotnetComponent };
        var sbomPackage = scannedComponent.ToSbomPackage(new AdapterReport(), this.osUtils.Object);
        Assert.IsNull(sbomPackage);
    }

    private void AssertPackageUrlIsCorrect(PackageUrl.PackageURL expectedPackageUrl, string actualPackageUrl)
    {
        if (expectedPackageUrl is null)
        {
            Assert.IsNull(actualPackageUrl);
            return;
        }

        Assert.AreEqual(expectedPackageUrl.ToString(), actualPackageUrl);
    }

    private (AdapterReport report, List<SbomPackage> packages) GenerateJsonFileForTestAndRun(string json)
    {
        var baseDirectory = Path.Combine(TestContext.TestRunDirectory, Guid.NewGuid().ToString());
        var bcdeOutputPath = Path.Combine(baseDirectory, "bcde-output.json");

        Directory.CreateDirectory(baseDirectory);
        File.WriteAllText(bcdeOutputPath, json);

        var adapter = new ComponentDetectionToSbomPackageAdapter(this.osUtils.Object);
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
