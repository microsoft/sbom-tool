// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api;

/// <summary>
/// Responsible for an API to generate SBOMs.
/// </summary>
public class SbomConsolidator : ISbomConsolidator
{
    private readonly IWorkflow<SbomConsolidationWorkflow> generationWorkflow;
    private readonly IRecorder recorder;

    public SbomConsolidator(
        IWorkflow<SbomConsolidationWorkflow> generationWorkflow,
        IRecorder recorder)
    {
        this.generationWorkflow = generationWorkflow;
        this.recorder = recorder;
    }

    /// <inheritdoc />
    public async Task<SbomConsolidationResult> ConsolidateSbomsAsync()
    {
        var result = new SbomConsolidationResult { IsSuccessful = await generationWorkflow.RunAsync() };

        await recorder.FinalizeAndLogTelemetryAsync();

        return result;
    }
}
