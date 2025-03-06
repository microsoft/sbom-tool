// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config;

public class Validator : ISbomService<ValidationArgs>
{
    private readonly IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow;

    private readonly IConfiguration configuration;

    private readonly IRecorder recorder;

    public Validator(
        IConfiguration configuration,
        IWorkflow<SbomParserBasedValidationWorkflow> parserValidationWorkflow,
        IRecorder recorder)
    {
        this.parserValidationWorkflow = parserValidationWorkflow;
        this.configuration = configuration;
        this.recorder = recorder;
    }

    public async Task<bool> Validate()
    {
        bool result;
        try
        {
            result = await parserValidationWorkflow.RunAsync();

            await recorder.FinalizeAndLogTelemetryAsync();
        }
        catch (Exception e)
        {
            var message = e.InnerException != null ? e.InnerException.Message : e.Message;
            Console.WriteLine($"Encountered error while running SBOM Tool validation workflow. Error: {message}");
            result = true;
        }

        return !result;
    }
}
