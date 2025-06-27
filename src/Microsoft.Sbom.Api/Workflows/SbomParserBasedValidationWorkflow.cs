// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows;

/// <summary>
/// Validates a SBOM against a given drop path. Uses the <see cref="ISbomParser"/> to read
/// objects inside a SBOM.
/// </summary>
public class SbomParserBasedValidationWorkflow : SbomValidationWorkflowBase, IWorkflow<SbomParserBasedValidationWorkflow>
{
    private readonly IConfiguration configuration;
    private readonly ISbomConfigProvider sbomConfigs;

    public SbomParserBasedValidationWorkflow(IRecorder recorder, ISignValidationProvider signValidationProvider, ILogger log, IManifestParserProvider manifestParserProvider, IConfiguration configuration, ISbomConfigProvider sbomConfigs, FilesValidator filesValidator, ValidationResultGenerator validationResultGenerator, IOutputWriter outputWriter, IFileSystemUtils fileSystemUtils, IOSUtils osUtils)
        : base(recorder, signValidationProvider, log, manifestParserProvider, filesValidator, validationResultGenerator, outputWriter, fileSystemUtils, osUtils)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
    }

    public async Task<bool> RunAsync()
    {
        var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo.Value.FirstOrDefault());
        return await ValidateAsync(sbomConfig, Events.SbomValidationWorkflow, configuration.Conformance?.Value, !configuration.ValidateSignature?.Value ?? false, configuration.FailIfNoPackages?.Value ?? false, configuration.IgnoreMissing?.Value ?? false);
    }
}
