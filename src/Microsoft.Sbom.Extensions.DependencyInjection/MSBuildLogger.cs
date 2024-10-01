// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions.DependencyInjection;

using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Serilog;
using Serilog.Events;
using ILogger = Serilog.ILogger;

/// <summary>
/// A class to remap Errors logged from ComponentDetection assemblies to Warnings.
/// </summary>
public class MSBuildLogger : ILogger
{
    private readonly TaskLoggingHelper loggingHelper;

    public MSBuildLogger(TaskLoggingHelper loggingHelperToWrap)
    {
        loggingHelper = loggingHelperToWrap;
    }

    public void Write(LogEvent logEvent)
    {
        var logLevel = logEvent.Level;
        switch (logLevel)
        {
            case LogEventLevel.Debug:
                loggingHelper.LogMessage(MessageImportance.Low, logEvent.RenderMessage());
                break;
            case LogEventLevel.Information:
                loggingHelper.LogMessage(MessageImportance.High, logEvent.RenderMessage());
                break;
            case LogEventLevel.Warning:
                loggingHelper.LogWarning(logEvent.RenderMessage());
                break;
            case LogEventLevel.Error:
            case LogEventLevel.Fatal:
                loggingHelper.LogError(logEvent.RenderMessage());
                break;
            default:
                break;
        }
    }
}
