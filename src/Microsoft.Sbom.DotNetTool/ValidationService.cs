// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using IConfiguration = Microsoft.Sbom.Common.Config.IConfiguration;

namespace Microsoft.Sbom.Tool
{
    public class ValidationService : IHostedService
    {
        private readonly IWorkflow<SBOMValidationWorkflow> validationWorkflow;

        private readonly IWorkflow<SBOMParserBasedValidationWorkflow> parserValidationWorkflow;

        private readonly IConfiguration configuration;

        private readonly IRecorder recorder;

        public ValidationService(
            IConfiguration configuration,
            IWorkflow<SBOMValidationWorkflow> validationWorkflow,
            IWorkflow<SBOMParserBasedValidationWorkflow> parserValidationWorkflow,
            IRecorder recorder)
        {
            this.validationWorkflow = validationWorkflow;
            this.parserValidationWorkflow = parserValidationWorkflow;
            this.configuration = configuration;
            this.recorder = recorder;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            bool result;
            try
            {
                if (configuration.ManifestInfo.Value.Contains(Api.Utils.Constants.SPDX22ManifestInfo))
                {
                    result = await parserValidationWorkflow.RunAsync();
                }
                else
                {
                    // On deprecation path.
                    Console.WriteLine($"This validation workflow is soon going to be deprecated. Please switch to the SPDX validation.");
                    result = await validationWorkflow.RunAsync();
                }

                await recorder.FinalizeAndLogTelemetryAsync();
            }
            catch (Exception e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool validation workflow. Error: {message}");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Environment.ExitCode = (int)ExitCode.Success;
            return Task.CompletedTask;
        }
    }
}
