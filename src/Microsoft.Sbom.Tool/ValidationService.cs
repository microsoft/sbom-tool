// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using IConfiguration = Microsoft.Sbom.Common.Config.IConfiguration;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Tool;

public class ValidationService : IHostedService
{
    private readonly IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow;

    private readonly IConfiguration configuration;

    private readonly IRecorder recorder;

    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public ValidationService(
        IConfiguration configuration,
        IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow,
        IRecorder recorder,
        IHostApplicationLifetime hostApplicationLifetime)
    {
        this.parserValidationWorkflow = parserValidationWorkflow;
        this.configuration = configuration;
        this.recorder = recorder;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        bool result;
        try
        {
            if (configuration.ManifestInfo.Value.Any(SpdxConstants.SupportedSpdxManifests.Contains))
            {
                result = await parserValidationWorkflow.RunAsync();
            }
            else
            {
                throw new ConfigurationException($"Validation only supports the SPDX2.2 and SPDX3.0 format.");
            }

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
