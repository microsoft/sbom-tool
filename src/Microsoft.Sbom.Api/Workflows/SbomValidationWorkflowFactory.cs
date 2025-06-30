// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows;

using System;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

public class SbomValidationWorkflowFactory : ISbomValidationWorkflowFactory
{
    private readonly IRecorder recorder;
    private readonly ISignValidationProvider signValidationProvider;
    private readonly ILogger log;
    private readonly IManifestParserProvider manifestParserProvider;
    private readonly FilesValidator filesValidator;
    private readonly ValidationResultGenerator validationResultGenerator;
    private readonly IOutputWriter outputWriter;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IOSUtils osUtils;

    public SbomValidationWorkflowFactory(
        IRecorder recorder,
        ISignValidationProvider signValidationProvider,
        ILogger log,
        IManifestParserProvider manifestParserProvider,
        FilesValidator filesValidator,
        ValidationResultGenerator validationResultGenerator,
        IOutputWriter outputWriter,
        IFileSystemUtils fileSystemUtils,
        IOSUtils osUtils)
    {
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.signValidationProvider = signValidationProvider ?? throw new ArgumentNullException(nameof(signValidationProvider));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.manifestParserProvider = manifestParserProvider ?? throw new ArgumentNullException(nameof(manifestParserProvider));
        this.filesValidator = filesValidator ?? throw new ArgumentNullException(nameof(filesValidator));
        this.validationResultGenerator = validationResultGenerator ?? throw new ArgumentNullException(nameof(validationResultGenerator));
        this.outputWriter = outputWriter ?? throw new ArgumentNullException(nameof(outputWriter));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
    }

    public IWorkflow<SbomParserBasedValidationWorkflow> Get(IConfiguration configuration, ISbomConfig sbomConfig, string eventName)
    {
        return new SbomParserBasedValidationWorkflow(recorder, signValidationProvider, log, manifestParserProvider, configuration, sbomConfig, filesValidator, validationResultGenerator, outputWriter, fileSystemUtils, osUtils, eventName);
    }
}
