// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog.Events;
using IComponentDetector = Microsoft.Sbom.Api.Utils.IComponentDetector;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class SBOMComponentsWalkerTests
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IConfiguration> mockConfiguration = new Mock<IConfiguration>();
    private readonly Mock<ISbomConfigProvider> mockSbomConfigs = new Mock<ISbomConfigProvider>();
    private readonly Mock<IFileSystemUtils> mockFileSystem = new Mock<IFileSystemUtils>();
    private readonly Mock<ILicenseInformationFetcher> mockLicenseInformationFetcher = new Mock<ILicenseInformationFetcher>();

    public SBOMComponentsWalkerTests()
    {
        ISbomConfig sbomConfig = new SbomConfig(mockFileSystem.Object)
        {
            ManifestJsonFilePath = "testpath"
        };
        mockConfiguration.SetupGet(c => c.Verbosity).Returns(new ConfigurationSetting<LogEventLevel> { Value = LogEventLevel.Information });
        mockSbomConfigs.Setup(s => s.TryGet(It.IsAny<ManifestInfo>(), out sbomConfig)).Returns(true);
    }

    [TestMethod]
    public async Task GetComponents()
    {
        var scannedComponents = new List<ScannedComponentWithLicense>();
        for (int i = 1; i < 4; i++)
        {
            var scannedComponent = new ScannedComponentWithLicense
            {
                Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), "componentName", $"123{i}", "abcdef", $"path{i}"),
                DetectorId = "SPDX22SBOM"
            };

            scannedComponents.Add(scannedComponent);
        }

        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Success,
            ComponentsFound = scannedComponents
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new SBOMComponentsWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystem.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");

        var discoveredComponents = await packagesChannelReader.output.ReadAllAsync().ToListAsync();

        await foreach (ComponentDetectorException error in packagesChannelReader.error.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.Message}");
        }

        Assert.IsTrue(scannedComponents.Count == discoveredComponents.Count);
        mockDetector.VerifyAll();
    }

    [TestMethod]
    public async Task GetComponentsWithFiltering()
    {
        var scannedComponents = new List<ScannedComponentWithLicense>();
        for (int i = 1; i < 4; i++)
        {
            var scannedComponent = new ScannedComponentWithLicense
            {
                Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.uri"), "componentName", $"123{i}", "abcdef", $"path{i}"),
                DetectorId = "SPDX22SBOM"
            };

            scannedComponents.Add(scannedComponent);
        }

        var nonSbomComponent = new ScannedComponentWithLicense
        {
            Component = new NpmComponent("componentName", "123"),
            DetectorId = "notSPDX22SBOM"
        };
        scannedComponents.Add(nonSbomComponent);

        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Success,
            ComponentsFound = scannedComponents
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new SBOMComponentsWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystem.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");

        var discoveredComponents = await packagesChannelReader.output.ReadAllAsync().ToListAsync();

        await foreach (ComponentDetectorException error in packagesChannelReader.error.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.Message}");
        }

        Assert.IsTrue(scannedComponents.Where(c => c.Component is SpdxComponent).ToList().Count == discoveredComponents.Count);
        mockDetector.VerifyAll();
    }
}