// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows;

using System;
using System.Threading.Tasks;
using Serilog;

public class SbomConsolidationWorkflow : IWorkflow<SbomConsolidationWorkflow>
{
    private readonly ILogger logger;

    public SbomConsolidationWorkflow(ILogger logger)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
#pragma warning disable CS1998 // Placeholder, will use async in the future.
    public virtual async Task<bool> RunAsync()
    {
        // Placeholder for the actual implementation of the SBOM consolidation workflow.
        // This method should contain the logic to consolidate SBOMs as per the requirements.
        // For now, it logs and returns true to indicate success.
        logger.Information("Placeholder SBOM consolidation workflow executed.");
        return true;
    }
#pragma warning restore CS1998 // Placeholder, will use async in the future.
}
