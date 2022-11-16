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

namespace Microsoft.Sbom.Tool
{

    public class GenerationService : IHostedService
    {
        private readonly IWorkflow<SBOMGenerationWorkflow> generationWorkflow;

        private readonly IRecorder recorder;

        public GenerationService(
            IWorkflow<SBOMGenerationWorkflow> generationWorkflow,
            IRecorder recorder)
        {
            this.generationWorkflow = generationWorkflow;
            this.recorder = recorder;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                var result = await generationWorkflow.RunAsync();
                await recorder.FinalizeAndLogTelemetryAsync();
            }
            catch (AccessDeniedValidationArgException e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
            }
            catch (Exception e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Environment.ExitCode = (int)ExitCode.Success;
            return Task.CompletedTask;
        }
    }
}
