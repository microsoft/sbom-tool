// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;

namespace Microsoft.Sbom.Api.Config
{
    public class Generator : ISbomService<GenerationArgs>
    {
        private readonly IWorkflow<SbomGenerationWorkflow> generationWorkflow;

        private readonly IRecorder recorder;

        public Generator(
            IWorkflow<SbomGenerationWorkflow> generationWorkflow,
            IRecorder recorder) 
        {
            this.generationWorkflow = generationWorkflow;
            this.recorder = recorder;
        }

        public async Task<(bool IsFailed, bool IsAccessError)> Generate()
        {
            bool isFailed;
            bool isAccessError = default;

            try
            {
                var result = await generationWorkflow.RunAsync();
                await recorder.FinalizeAndLogTelemetryAsync();
                isFailed = !result;
            }
            catch (AccessDeniedValidationArgException e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
                isFailed = true;
                isAccessError = true;
            }
            catch (Exception e)
            {
                var message = e.InnerException != null ? e.InnerException.Message : e.Message;
                Console.WriteLine($"Encountered error while running ManifestTool generation workflow. Error: {message}");
                isFailed = true;
            }

            return (IsFailed: isFailed, IsAccessError: isAccessError);
        }
    }
}
