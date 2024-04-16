// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using Serilog.Events;
using Serilog.Parsing;

namespace Microsoft.Sbom.Extensions.DependencyInjection.Tests;

[TestClass]
public class RemapComponentDetectionErrorsToWarningsLoggerTests
{
    private const string TestPropertyKey = "TestPropertyKey";

    private Mock<ILogger> loggerMock;
    private Func<string> stackTraceProvider;
    private ILogger testSubject;
    private int testStackTraceCount;
    private string? testStackTraceReturnValue;

    // We need a concrete implementation of MessageTemplateToken
    internal class TestMessageTemplateToken : MessageTemplateToken
    {
        public override int Length => throw new NotImplementedException();

        public override void Render(IReadOnlyDictionary<string, LogEventPropertyValue> properties, TextWriter output, IFormatProvider formatProvider = null) => throw new NotImplementedException();
    }

    // We need a concrete implementation of LogEventPropertyValue
    internal class TestLogEventPropertyValue : LogEventPropertyValue
    {
        public override void Render(TextWriter output, string format = null, IFormatProvider formatProvider = null) => throw new NotImplementedException();
    }

    [TestInitialize]
    public void TestInit()
    {
        loggerMock = new Mock<ILogger>(MockBehavior.Strict);
        stackTraceProvider = TestGetStackTrace;
        testStackTraceCount = 0;
        testStackTraceReturnValue = null;
        testSubject = new RemapComponentDetectionErrorsToWarningsLogger(loggerMock.Object, stackTraceProvider);
    }

    [TestCleanup]
    public void TestCleanup()
    {
        loggerMock.VerifyAll();
    }

    [TestMethod]
    public void Constructor_LoggerIsNull_ThrowsNullArgumentException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new RemapComponentDetectionErrorsToWarningsLogger(null, stackTraceProvider));
    }

    [TestMethod]
    public void Constructor_StackTraceProviderIsNull_ThrowsNullArgumentException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new RemapComponentDetectionErrorsToWarningsLogger(loggerMock.Object, null));
    }

    [TestMethod]
    public void Write_LogEventLevelIsNotError_DoesNotCallStackTraceProvider_LogsEventAsSpecified()
    {
        var nonErrorLevels = Enum.GetValues(typeof(LogEventLevel)).Cast<LogEventLevel>().Where((x) => x != LogEventLevel.Error);
        foreach (var level in nonErrorLevels)
        {
            var logEvent = GetLogEvent(level);
            loggerMock.Setup(x => x.Write(logEvent)).Verifiable();

            testSubject.Write(logEvent);

            Assert.AreEqual(0, testStackTraceCount);

            // The VerifyAll and Reset calls are needed here because we need to confirm them for _each iteration_ of the loop.
            loggerMock.VerifyAll();
            loggerMock.Reset();
        }
    }

    [TestMethod]
    public void Write_LogEventLevelIsError_StackTraceReturnsNull_LogsEventAsSpecified()
    {
        var logEvent = GetLogEvent(LogEventLevel.Error);
        loggerMock.Setup(x => x.Write(logEvent)).Verifiable();

        testSubject.Write(logEvent);

        Assert.AreEqual(1, testStackTraceCount);
    }

    [TestMethod]
    public void Write_LogEventLevelIsError_StackTraceDoesNotContainComponentDetection_LogsEventAsSpecified()
    {
        var logEvent = GetLogEvent(LogEventLevel.Error);
        loggerMock.Setup(x => x.Write(logEvent)).Verifiable();
        testStackTraceReturnValue = "at Microsoft.Sbom.Foo.Bar";

        testSubject.Write(logEvent);

        Assert.AreEqual(1, testStackTraceCount);
    }

    [TestMethod]
    public void Write_LogEventLevelIsError_StackTraceContainsComponentDetection_LogsEventAsWarning()
    {
        LogEvent actualEvent = null;
        var logEvent = GetLogEvent(LogEventLevel.Error);
        loggerMock.Setup(x => x.Write(It.IsAny<LogEvent>())).Callback<LogEvent>((l) => actualEvent = l).Verifiable();
        testStackTraceReturnValue = "at Microsoft.ComponentDetection.Foo.Bar";

        testSubject.Write(logEvent);

        Assert.AreEqual(1, testStackTraceCount);

        // Ensure that the LogEvent was correctly copied. Only the Level should be different
        Assert.AreEqual(LogEventLevel.Warning, actualEvent.Level);
        Assert.AreEqual(logEvent.Timestamp, actualEvent.Timestamp);
        Assert.AreSame(logEvent.MessageTemplate, actualEvent.MessageTemplate);
        Assert.AreEqual(logEvent.Properties.Count, actualEvent.Properties.Count);
        Assert.AreEqual(1, actualEvent.Properties.Count);
        Assert.IsInstanceOfType(logEvent.Properties[TestPropertyKey], typeof(TestLogEventPropertyValue));
        Assert.AreSame(logEvent.Properties[TestPropertyKey], actualEvent.Properties[TestPropertyKey]);
    }

    // A helper function to return a LogEvent with the specified LogEventLevel
    private LogEvent GetLogEvent(LogEventLevel logEventLevel)
    {
        return new LogEvent(
            DateTimeOffset.Now,
            logEventLevel,
            null,
            new MessageTemplate(new List<MessageTemplateToken> { new TestMessageTemplateToken() }),
            new LogEventProperty[1] { new LogEventProperty(TestPropertyKey, new TestLogEventPropertyValue()) });
    }

    // A helper function to allow us to easily test the StackTraceProvider functionality
    private string TestGetStackTrace()
    {
        testStackTraceCount++;
        return testStackTraceReturnValue;
    }
}
