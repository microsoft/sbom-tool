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
public class PackagesWalkerTests
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private readonly Mock<IConfiguration> mockConfiguration = new Mock<IConfiguration>();
    private readonly Mock<ISbomConfigProvider> mockSbomConfigs = new Mock<ISbomConfigProvider>();
    private readonly Mock<IFileSystemUtils> mockFileSystemUtils = new Mock<IFileSystemUtils>();
    private readonly Mock<ILicenseInformationFetcher> mockLicenseInformationFetcher = new Mock<ILicenseInformationFetcher>();

    public PackagesWalkerTests()
    {
        ISbomConfig sbomConfig = new SbomConfig(mockFileSystemUtils.Object)
        {
            ManifestJsonFilePath = "testpath"
        };
        mockConfiguration.SetupGet(c => c.Verbosity).Returns(new ConfigurationSetting<LogEventLevel> { Value = LogEventLevel.Information });
        mockSbomConfigs.Setup(s => s.TryGet(It.IsAny<ManifestInfo>(), out sbomConfig)).Returns(true);
    }

    [TestMethod]
    public async Task ScanSuccessTestAsync()
    {
        var scannedComponents = new List<ScannedComponentWithLicense>();
        for (var i = 1; i < 4; i++)
        {
            var scannedComponent = new ScannedComponentWithLicense
            {
                Component = new NpmComponent("componentName", $"{i}")
            };

            scannedComponents.Add(scannedComponent);
        }

        var scannedComponentOther = new ScannedComponentWithLicense
        {
            Component = new NpmComponent("componentName", "3")
        };

        scannedComponents.Add(scannedComponentOther);

        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Success,
            ComponentsFound = scannedComponents
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new PackagesWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystemUtils.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");

        var countDistinctComponents = 0;

        await foreach (ScannedComponentWithLicense package in packagesChannelReader.output.ReadAllAsync())
        {
            countDistinctComponents++;
            Assert.IsTrue(scannedComponents.Remove(package));
        }

        await foreach (var error in packagesChannelReader.error.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.Message}");
        }

        Assert.IsTrue(scannedComponents.Count == 1);
        Assert.IsTrue(countDistinctComponents == 3);
        mockDetector.VerifyAll();
    }

    [TestMethod]
    public async Task ScanCombinePackagesWithSameNameDifferentCase()
    {
        var scannedComponents = new List<ScannedComponentWithLicense>();
        for (var i = 1; i < 4; i++)
        {
            var scannedComponent = new ScannedComponentWithLicense
            {
                Component = new NpmComponent("componentName", $"{i}")
            };

            scannedComponents.Add(scannedComponent);
        }

        var scannedComponentOther = new ScannedComponentWithLicense
        {
            // Component with changed case. should also match 'componentName' and
            // thus only 3 components should be detected.
            Component = new NpmComponent("ComponentName", "3")
        };

        scannedComponents.Add(scannedComponentOther);

        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Success,
            ComponentsFound = scannedComponents
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new PackagesWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystemUtils.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");

        var countDistinctComponents = 0;

        await foreach (ScannedComponentWithLicense package in packagesChannelReader.output.ReadAllAsync())
        {
            countDistinctComponents++;
            Assert.IsTrue(scannedComponents.Remove(package));
        }

        await foreach (var error in packagesChannelReader.error.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.Message}");
        }

        Assert.IsTrue(scannedComponents.Count == 1);
        Assert.IsTrue(countDistinctComponents == 3);
        mockDetector.VerifyAll();
    }

    [TestMethod]
    public void ScanWithNullOrEmptyPathSuccessTest()
    {
        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var walker = new PackagesWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystemUtils.Object, mockLicenseInformationFetcher.Object);
        walker.GetComponents(null);
        walker.GetComponents(string.Empty);

        mockDetector.Verify(mock => mock.ScanAsync(It.IsAny<string[]>()), Times.Never());
    }

    [TestMethod]
    public async Task ScanFailureTestAsync()
    {
        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Error,
            ComponentsFound = null
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new PackagesWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystemUtils.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");
        ComponentDetectorException actualError = null;

        await foreach (var package in packagesChannelReader.output.ReadAllAsync())
        {
            Assert.Fail("Packages were still returned when the detector failed.");
        }

        await foreach (var error in packagesChannelReader.error.ReadAllAsync())
        {
            actualError = error;
        }

        Assert.IsNotNull(actualError);
        mockDetector.VerifyAll();
    }

    [TestMethod]
    public async Task ScanIgnoreSbomComponents()
    {
        var scannedComponents = new List<ScannedComponentWithLicense>();
        for (var i = 1; i < 4; i++)
        {
            var scannedComponent = new ScannedComponentWithLicense
            {
                Component = new NpmComponent("componentName", $"{i}")
            };

            scannedComponents.Add(scannedComponent);
        }

        var scannedComponentOther = new ScannedComponentWithLicense
        {
            Component = new SpdxComponent("SPDX-2.2", new Uri("http://test.com"), "componentName", "123", "abcdf", "path1")
        };

        scannedComponents.Add(scannedComponentOther);

        var mockDetector = new Mock<ComponentDetectorCachedExecutor>(new Mock<ILogger>().Object, new Mock<IComponentDetector>().Object);

        var scanResult = new ScanResult
        {
            ResultCode = ProcessingResultCode.Success,
            ComponentsFound = scannedComponents
        };

        mockDetector.Setup(o => o.ScanAsync(It.IsAny<string[]>())).Returns(Task.FromResult(scanResult));
        var walker = new PackagesWalker(mockLogger.Object, mockDetector.Object, mockConfiguration.Object, mockSbomConfigs.Object, mockFileSystemUtils.Object, mockLicenseInformationFetcher.Object);
        var packagesChannelReader = walker.GetComponents("root");

        var discoveredComponents = await packagesChannelReader.output.ReadAllAsync().ToListAsync();

        await foreach (var error in packagesChannelReader.error.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.Message}");
        }

        Assert.IsTrue(scannedComponents.Where(c => !(c.Component is SpdxComponent)).ToList().Count == discoveredComponents.Count);
        mockDetector.VerifyAll();
    }
}
