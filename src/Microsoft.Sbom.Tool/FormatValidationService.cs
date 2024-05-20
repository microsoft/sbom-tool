// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Tool;

public class FormatValidationService : IHostedService
{
    private readonly IConfiguration config;
    private readonly IRecorder recorder;
    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public FormatValidationService(IConfiguration config,
        IRecorder recorder,
        IHostApplicationLifetime hostApplicationLifetime)
    {
        this.config = config;
        this.recorder = recorder;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            Console.WriteLine($"Format validation service called for {config.SbomPath.Value}");

            await recorder.FinalizeAndLogTelemetryAsync();
            Environment.ExitCode = true ? (int)ExitCode.Success : (int)ExitCode.ValidationError;
        }
        catch (Exception e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running format validation. Error: {message}");
            Environment.ExitCode = (int)ExitCode.GeneralError;
        }

        hostApplicationLifetime.StopApplication();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
