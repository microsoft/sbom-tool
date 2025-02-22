// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.FormatValidator;
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

    private void PrintLines(List<string> lines)
    {
        foreach (var line in lines)
        {
            Console.WriteLine(line);
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            using (var sbomStream = new StreamReader(config.SbomPath.Value))
            {
                var validatedSbom = new ValidatedSbom(sbomStream.BaseStream);
                PrintLines(await validatedSbom.MultilineSummary());
            }

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
        Environment.Exit(Environment.ExitCode);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
