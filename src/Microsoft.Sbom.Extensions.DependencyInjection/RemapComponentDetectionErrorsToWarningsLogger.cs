// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions.DependencyInjection;

using System;
using Serilog;
using Serilog.Events;

/// <summary>
/// A class to remap Errors logged from ComponentDetection assemblies to Warnings.
/// </summary>
public class RemapComponentDetectionErrorsToWarningsLogger : ILogger
{
    private readonly ILogger logger;
    private readonly Func<string?> stackTraceProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="RemapComponentDetectionErrorsToWarningsLogger"/> class.
    /// Production constructor.
    /// </summary>
    public RemapComponentDetectionErrorsToWarningsLogger(ILogger logger)
        : this(logger, () => Environment.StackTrace)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RemapComponentDetectionErrorsToWarningsLogger"/> class.
    /// Testable constructor.
    /// </summary>
    /// <exception cref="ArgumentNullException"></exception>
    internal RemapComponentDetectionErrorsToWarningsLogger(ILogger logger, Func<string?> stackTraceProvider)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.stackTraceProvider = stackTraceProvider ?? throw new ArgumentNullException(nameof(stackTraceProvider));
    }

    /// <inheritdoc />
    /// <remarks>If ComponentDetection is on the stack, remap and log Errors to Warnings.</remarks>
    public void Write(LogEvent logEvent)
    {
        // For performance reasons, bypass StackTrace work for non-errors.
        if (logEvent.Level == LogEventLevel.Error)
        {
            var stackTrace = stackTraceProvider();
            if (stackTrace is not null && stackTrace.Contains("Microsoft.ComponentDetection."))
            {
                var warningLogEvent = new LogEvent(
                    logEvent.Timestamp,
                    LogEventLevel.Warning,
                    logEvent.Exception,
                    logEvent.MessageTemplate,
                    logEvent.Properties.Select(kvp => new LogEventProperty(kvp.Key, kvp.Value)));

                logger.Write(warningLogEvent);
                return;
            }
        }

        logger.Write(logEvent);
    }
}
