// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api;

/// <summary>
/// Responsible for an API to aggregate SBOMs.
/// </summary>
public class SbomAggegator : ISbomAggregator
{
    private readonly IWorkflow<SbomAggregationWorkflow> aggregationWorkflow;
    private readonly IRecorder recorder;

    public SbomAggegator(
        IWorkflow<SbomAggregationWorkflow> aggregationWorkflow,
        IRecorder recorder)
    {
        this.aggregationWorkflow = aggregationWorkflow;
        this.recorder = recorder;
    }

    /// <inheritdoc />
    public async Task<SbomAggregationResult> AggregateSbomsAsync()
    {
        var isSuccessful = await aggregationWorkflow.RunAsync();

        await recorder.FinalizeAndLogTelemetryAsync();

        var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

        return new SbomAggregationResult(isSuccessful, entityErrors);
    }
}
