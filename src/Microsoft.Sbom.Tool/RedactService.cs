// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;

namespace Microsoft.Sbom.Tool;

public class RedactService : IHostedService
{
    private readonly IWorkflow<SbomRedactionWorkflow> redactionWorkflow;
    private readonly IRecorder recorder;
    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public RedactService(
        IWorkflow<SbomRedactionWorkflow> redactionWorkflow,
        IRecorder recorder,
        IHostApplicationLifetime hostApplicationLifetime)
    {
        this.redactionWorkflow = redactionWorkflow;
        this.recorder = recorder;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await redactionWorkflow.RunAsync();
            await recorder.FinalizeAndLogTelemetryAsync();
            Environment.ExitCode = result ? (int)ExitCode.Success : (int)ExitCode.GeneralError;
        }
        catch (Exception e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running ManifestTool redaction workflow. Error: {message}");
            Environment.ExitCode = (int)ExitCode.GeneralError;
        }

        hostApplicationLifetime.StopApplication();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
