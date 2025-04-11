// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Serilog.Events;
using ILogger = Serilog.ILogger;

/// <summary>
/// A class to remap Errors logged from ComponentDetection assemblies to Warnings or Errors in MSBuild from Serilog to MSBuild's native logging facilities. This class interprets a few kinds of properties from the
/// logged Serilog message:
/// <list type="bullet">
/// <item><description><c>msbuild.code</c> becomes the <c>code</c> for the <see cref="TaskLoggingHelper.LogWarning(string, string, string, string, string, int, int, int, int, string, object[])" /> or <see cref="TaskLoggingHelper.LogError(string, string, string, string, string, int, int, int, int, string, object[])"/> methods for Serilog <see cref="LogEventLevel.Warning"/>, <see cref="LogEventLevel.Error"/>, and <see cref="LogEventLevel.Fatal"/> events.</description></item>
/// <item><description><c>msbuild.importance</c> becomes the <c>importance</c> for the <see cref="TaskLoggingHelper.LogMessage(MessageImportance, string, object[])" /> method for Serilog <see cref="LogEventLevel.Debug"/> and <see cref="LogEventLevel.Information"/> events.</description></item>
/// </list>
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
        if (logLevel is LogEventLevel.Warning && logEvent.Properties.TryGetValue("SourceContext", out var lepv) && lepv is ScalarValue sv && sv.Value is string svv && svv.StartsWith("Microsoft.ComponentDetection", StringComparison.Ordinal))
        {
            // Component Detection fires a lot of warnings, translate these to Information
            logLevel = LogEventLevel.Information;
        }

        switch (logLevel)
        {
            case LogEventLevel.Debug:
                logEvent.Properties.TryGetValue("msbuild.importance", out var debugImportance);
                loggingHelper.LogMessage(TryParseImportance(debugImportance) ?? MessageImportance.Low, logEvent.RenderMessage());
                break;
            case LogEventLevel.Information:
                logEvent.Properties.TryGetValue("msbuild.importance", out var infoImportance);
                loggingHelper.LogMessage(TryParseImportance(infoImportance) ?? MessageImportance.Normal, logEvent.RenderMessage());
                break;
            // warnings and errors can have codes, etc - if the message has a code then use it
            case LogEventLevel.Warning:
                logEvent.Properties.TryGetValue("msbuild.code", out var warningCode);
                loggingHelper.LogWarning(subcategory: null, warningCode: warningCode?.ToString(), helpKeyword: null, helpLink: null, file: null, lineNumber: 0, columnNumber: 0, endLineNumber: 0, endColumnNumber: 0, message: logEvent.RenderMessage());
                break;
            case LogEventLevel.Error:
            case LogEventLevel.Fatal:
                logEvent.Properties.TryGetValue("msbuild.code", out var errorCode);
                loggingHelper.LogError(subcategory: null, errorCode: errorCode?.ToString(), helpKeyword: null, helpLink: null, file: null, lineNumber: 0, columnNumber: 0, endLineNumber: 0, endColumnNumber: 0, message: logEvent.RenderMessage());
                break;
            default:
                break;
        }
    }

    private MessageImportance? TryParseImportance(LogEventPropertyValue? infoImportance) =>
        infoImportance != null && Enum.TryParse<MessageImportance>(infoImportance.ToString(), out var msbuildImportance) ? msbuildImportance : null;
}
