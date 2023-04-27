// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;

namespace Microsoft.Sbom.Api;

public class SbomValidator : ISBOMValidator
{
    private readonly IWorkflow<SbomParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow;
    private readonly IRecorder recorder;

    public SbomValidator(
        IWorkflow<SbomParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow,
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