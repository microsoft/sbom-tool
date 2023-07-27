// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Extensions.Logging;
using Serilog.Events;

public class SerilogLoggerConverter<T> : ILogger<T>
{
    private readonly Serilog.ILogger serilogLogger;

    public SerilogLoggerConverter(Serilog.ILogger logger)
    {
        serilogLogger = logger;
    }

    public IDisposable BeginScope<TState>(TState state)
    {
        // Use the PushProperty method to push the state as a property into the Serilog context
        return Serilog.Context.LogContext.PushProperty("Scope", state);
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return serilogLogger.IsEnabled(ConvertLogLevel(logLevel));
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
    {
        var serilogLogLevel = ConvertLogLevel(logLevel);
        if (serilogLogger.IsEnabled(serilogLogLevel)) // Check the log level before logging
        {
            serilogLogger.Write(serilogLogLevel, exception, formatter(state, exception));
        }
    }

    private LogEventLevel ConvertLogLevel(LogLevel logLevel)
    {
        return logLevel switch
        {
            LogLevel.Trace => LogEventLevel.Verbose,
            LogLevel.Debug => LogEventLevel.Debug,
            LogLevel.Information => LogEventLevel.Information,
            LogLevel.Warning => LogEventLevel.Warning,
            LogLevel.Error => LogEventLevel.Error,
            LogLevel.Critical => LogEventLevel.Fatal,
            _ => LogEventLevel.Information,
        };
    }
}