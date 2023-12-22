// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Extensions.Logging;
using Microsoft.ComponentDetection.Orchestrator.Commands;
using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class ComponentDetectorCachedExecutorTest
{
    private readonly Mock<ILogger<ComponentDetectorCachedExecutor>> logger = new Mock<ILogger<ComponentDetectorCachedExecutor>>();
    private readonly Mock<IComponentDetector> detector = new Mock<IComponentDetector>();

    [TestInitialize]
    public void TestInitialize()
    {
        logger.Reset();
        detector.Reset();
    }

    [TestMethod]
    public async Task Scan()
    {
        var executor = new ComponentDetectorCachedExecutor(logger.Object, detector.Object);
        var arguments = new ScanSettings { SourceDirectory = new DirectoryInfo("test"), Debug = true };
        var expectedResult = new ScanResult();

        detector.Setup(x => x.ScanAsync(arguments)).Returns(Task.FromResult(expectedResult));
        var result = await executor.ScanAsync(arguments);
        Assert.AreEqual(result, expectedResult);
        Assert.IsTrue(detector.Invocations.Count == 1);
    }

    [TestMethod]
    public async Task ScanWithCache()
    {
        var executor = new ComponentDetectorCachedExecutor(logger.Object, detector.Object);
        var arguments = new ScanSettings { SourceDirectory = new DirectoryInfo("test"), Debug = true };
        var expectedResult = new ScanResult();

        detector.Setup(x => x.ScanAsync(arguments)).Returns(Task.FromResult(expectedResult));
        await executor.ScanAsync(arguments);
        var result = await executor.ScanAsync(arguments);
        Assert.AreEqual(result, expectedResult);
        Assert.IsTrue(detector.Invocations.Count == 1);
    }
}
