// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

using System;
using System.Diagnostics;
using Serilog;

public class ProcessExecutor : IProcessExecutor
{
    private readonly ILogger logger;

    public ProcessExecutor(ILogger logger)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Wrapper for starting a process. Returns the standard output as a trimmed string.
    /// </summary>
    /// <param name="fileName">File/Program to be executed.</param>
    /// <param name="arguments">Arguments to be supplied to the executable.</param>
    /// <param name="timeoutInMilliseconds">Timeout for the process being executed.</param>
    /// <returns></returns>
    public string? ExecuteCommand(string fileName, string arguments, int timeoutInMilliseconds)
    {
        var processStartInformation = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process();
        process.StartInfo = processStartInformation;

        process.Start();

        var processExited = process.WaitForExit(timeoutInMilliseconds);

        // Check if process was successful or not.
        if (process.ExitCode != 0)
        {
            logger.Error($"The process {fileName} with the arguments {arguments} exited with code {process.ExitCode}. StdErr: {process.StandardError.ReadToEnd()}");
            return null;
        }

        if (!processExited)
        {
            process.Kill(); // If the process exceeds the timeout, kill it
            logger.Error($"The process {fileName} with the arguments {arguments} timed out.");
            return null;
        }

        return process.StandardOutput.ReadToEnd()?.Trim().ToString();
    }
}
