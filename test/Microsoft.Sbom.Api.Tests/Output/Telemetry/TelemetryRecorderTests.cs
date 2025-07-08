// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
namespace Microsoft.Sbom.Api.Output.Telemetry.Tests;

using System.Collections.Generic;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

[TestClass]
public class TelemetryRecorderTests
{
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IConfiguration> configMock;
    private Mock<ILogger> loggerMock;

    [TestInitialize]
    public void Init()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        configMock = new Mock<IConfiguration>();
        loggerMock = new Mock<ILogger>();
    }

    [TestMethod]
    public void TelemetryRecorderTest_AddResult()
    {
        var telemetryRecorder = new TelemetryRecorder(fileSystemUtilsMock.Object, configMock.Object, loggerMock.Object);
        var testKey = "TestKey";
        var testValue1 = "TestValue";

        telemetryRecorder.AddResult(testKey, testValue1);

        var additionalResultsField = typeof(TelemetryRecorder).GetField("additionalResults", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var additionalResults = (Dictionary<string, string>)additionalResultsField.GetValue(telemetryRecorder);

        Assert.IsTrue(additionalResults.ContainsKey(testKey));
        Assert.AreEqual(testValue1, additionalResults[testKey]);

        var testValue2 = "AnotherTestValue";
        telemetryRecorder.AddResult(testKey, testValue2);
        Assert.AreEqual(testValue2, additionalResults[testKey]);
        Assert.AreNotEqual(testValue1, additionalResults[testKey]);
    }

    [TestMethod]
    public void AddAggregationSourceTelemetryTest()
    {
        const string testKey = "TestKey";

        var telemetryRecorder = new TelemetryRecorder(fileSystemUtilsMock.Object, configMock.Object, loggerMock.Object);
        var aggregationSourceTelemetry = new AggregationSourceTelemetry
        {
            PackageCount = 5,
            RelationShipCount = 10
        };

        telemetryRecorder.AddAggregationSourceTelemetry(testKey, aggregationSourceTelemetry);

        var telemetryField = typeof(TelemetryRecorder).GetField("aggregationSourceTelemetry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var telemetryResults = (Dictionary<string, AggregationSourceTelemetry>)telemetryField.GetValue(telemetryRecorder);

        Assert.AreEqual(1, telemetryResults.Count);
        Assert.AreSame(aggregationSourceTelemetry, telemetryResults[testKey]);
    }
}
