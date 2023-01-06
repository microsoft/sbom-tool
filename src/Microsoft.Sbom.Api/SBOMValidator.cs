// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using PowerArgs;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api
{
    public class SBOMValidator : ISBOMValidator
    {
        private readonly IWorkflow<SBOMParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow;
        private readonly IRecorder recorder;

        public SBOMValidator(
            IWorkflow<SBOMParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow,
            IRecorder recorder)
        {
            this.sbomParserBasedValidationWorkflow = sbomParserBasedValidationWorkflow ?? throw new ArgumentNullException(nameof(sbomParserBasedValidationWorkflow));
            this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        }

        public async Task<bool> ValidateSbomAsync()
        {
            bool isSuccess = await sbomParserBasedValidationWorkflow.RunAsync();
            await recorder.FinalizeAndLogTelemetryAsync();

            var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

            return isSuccess;
        }
    }
}
