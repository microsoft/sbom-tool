// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Output.Telemetry.Tests;

[TestClass]
public class TelemetryRecorderTests
{
    private Mock<IFileSystemUtils> fileSystemUtilsMock;
    private Mock<IConfiguration> configMock;
    private Mock<ILogger> loggerMock;

    [TestInitialize]
    public void Init()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>(MockBehavior.Strict);
        configMock = new Mock<IConfiguration>(MockBehavior.Strict);
        loggerMock = new Mock<ILogger>(MockBehavior.Strict);
    }

    [TestCleanup]
    public void AfterEachTest()
    {
        fileSystemUtilsMock.VerifyAll();
        configMock.VerifyAll();
        loggerMock.VerifyAll();
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
    public void RecordAggregationSource_NoDuplicate()
    {
        const string testKey = "TestKey";
        const int testPackageCount = 5;
        const int testRelationshipCount = 10;

        var telemetryRecorder = new TelemetryRecorder(fileSystemUtilsMock.Object, configMock.Object, loggerMock.Object);

        telemetryRecorder.RecordAggregationSource(testKey, testPackageCount, testRelationshipCount);

        var telemetryField = typeof(TelemetryRecorder).GetField("aggregationSourceTelemetry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var telemetryResults = (Dictionary<string, AggregationSourceTelemetry>)telemetryField.GetValue(telemetryRecorder);

        Assert.AreEqual(1, telemetryResults.Count);
        Assert.AreEqual(testPackageCount, telemetryResults[testKey].PackageCount);
        Assert.AreEqual(testRelationshipCount, telemetryResults[testKey].RelationshipCount);
    }

    [TestMethod]
    public void RecordAggregationSource_Duplicate_Throws()
    {
        const string testKey = "TestKey";
        const int testPackageCount = 5;
        const int testRelationshipCount = 10;

        var telemetryRecorder = new TelemetryRecorder(fileSystemUtilsMock.Object, configMock.Object, loggerMock.Object);

        telemetryRecorder.RecordAggregationSource(testKey, testPackageCount, testRelationshipCount);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            telemetryRecorder.RecordAggregationSource(testKey, testPackageCount, testRelationshipCount);
        });
    }
}
