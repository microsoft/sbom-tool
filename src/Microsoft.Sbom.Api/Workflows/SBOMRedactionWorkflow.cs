// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Tasks;
using Microsoft.Sbom.Common.Config;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows;

/// <summary>
/// The SBOM tool workflow class that is used to redact file information from a SBOM or set of SBOMs.
/// </summary>
public class SbomRedactionWorkflow : IWorkflow<SbomRedactionWorkflow>
{
    private readonly ILogger log;

    private readonly IConfiguration configuration;

    public SbomRedactionWorkflow(
        ILogger log,
        IConfiguration configuration)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public virtual async Task<bool> RunAsync()
    {
        log.Information($"Running redaction for SBOM path {configuration.SbomPath?.Value} and SBOM dir {configuration.SbomDir?.Value}. Output dir: {configuration.OutputPath?.Value}");
        return await Task.FromResult(true);
    }
}
