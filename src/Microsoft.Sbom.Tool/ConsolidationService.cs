// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;

namespace Microsoft.Sbom.Tool;

public class ConsolidationService : IHostedService
{
    private readonly IWorkflow<SbomConsolidationWorkflow> consolidationWorkflow;
    private readonly IRecorder recorder;
    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public ConsolidationService(
        IWorkflow<SbomConsolidationWorkflow> consolidationWorkflow,
        IRecorder recorder,
        IHostApplicationLifetime hostApplicationLifetime)
    {
        this.consolidationWorkflow = consolidationWorkflow;
        this.recorder = recorder;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await consolidationWorkflow.RunAsync();
            await recorder.FinalizeAndLogTelemetryAsync();
            Environment.ExitCode = result ? (int)ExitCode.Success : (int)ExitCode.GeneralError;
        }
        catch (AccessDeniedValidationArgException e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running ManifestTool consolidation workflow. Error: {message}");
            Environment.ExitCode = (int)ExitCode.WriteAccessError;
        }
        catch (Exception e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running ManifestTool consolidation workflow. Error: {message}");
            Environment.ExitCode = (int)ExitCode.GeneralError;
        }

        hostApplicationLifetime.StopApplication();
        Environment.Exit(Environment.ExitCode);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
