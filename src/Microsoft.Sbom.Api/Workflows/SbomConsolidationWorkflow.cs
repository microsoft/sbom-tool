// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Common.Config;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows;

public class SbomConsolidationWorkflow : IWorkflow<SbomConsolidationWorkflow>
{
    private readonly ILogger logger;
    private readonly IConfiguration configuration;

#pragma warning disable IDE0051 // We'll use this soon.
    private IReadOnlyDictionary<string, ArtifactInfo> ArtifactInfoMap => configuration.ArtifactInfoMap.Value;
#pragma warning restore IDE0051 // We'll use this soon.

    public SbomConsolidationWorkflow(ILogger logger, IConfiguration configuration)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    /// <inheritdoc/>
#pragma warning disable CS1998 // Placeholder, will use async in the future.
    public virtual async Task<bool> RunAsync()
    {
        logger.Information("Placeholder SBOM consolidation workflow executed.");

        return ValidateSourceSboms() && GeneratedConsolidatedSbom();
    }
#pragma warning restore CS1998 // Placeholder, will use async in the future.

    private bool ValidateSourceSboms()
    {
        // TODO : Implement the source SBOMs.
        return true;
    }

    private bool GeneratedConsolidatedSbom()
    {
        // TODO : Generate the consolidated SBOM.
        return true;
    }
}
