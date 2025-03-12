// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;

namespace Microsoft.Sbom.Tool;

public class ValidationService : IHostedService
{
    private readonly IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow;

    private readonly IRecorder recorder;

    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public ValidationService(
        IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow,
        IRecorder recorder,
        IHostApplicationLifetime hostApplicationLifetime)
    {
        this.parserValidationWorkflow = parserValidationWorkflow;
        this.recorder = recorder;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        bool result;
        try
        {
            result = await parserValidationWorkflow.RunAsync();

            await recorder.FinalizeAndLogTelemetryAsync();
            Environment.ExitCode = result ? (int)ExitCode.Success : (int)ExitCode.ValidationError;
        }
        catch (Exception e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running ManifestTool validation workflow. Error: {message}");
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
