// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Tests;

using System;
using System.IO;

/// <summary>
/// A simple class to capture console output. Always wrap it in a try/finally block to
/// ensure that the original console output is restored.
/// </summary>
internal class ConsoleCapture
{
    private readonly TextWriter oldStdOut = Console.Out;
    private readonly TextWriter oldStdError = Console.Error;
    private TextWriter? stdOutWriter;
    private TextWriter? stdErrWriter;

    /// <summary>
    /// The content of the captured output to StdOut. Is only valid after the Restore method has been called.
    /// </summary>
    public string CapturedStdOut { get; private set; } = string.Empty;

    /// <summary>
    /// The content of the captured output to StdError. Is only valid after the Restore method has been called.
    /// </summary>
    public string CapturedStdError { get; private set; } = string.Empty;

    public ConsoleCapture()
    {
        stdOutWriter = new StringWriter();
        Console.SetOut(stdOutWriter);

        stdErrWriter = new StringWriter();
        Console.SetError(stdErrWriter);
    }

    /// <summary>
    /// Restores the original console output and sets the Captured* properties
    /// </summary>
    public void Restore()
    {
        if (stdOutWriter is not null)
        {
            CapturedStdOut = stdOutWriter?.ToString() ?? string.Empty;
            Console.SetOut(oldStdOut);
            stdOutWriter?.Dispose();
            stdOutWriter = null;
        }

        if (stdErrWriter is not null)
        {
            CapturedStdError = stdErrWriter?.ToString() ?? string.Empty;
            Console.SetError(oldStdError);
            stdErrWriter?.Dispose();
            stdErrWriter = null;
        }
    }
}
