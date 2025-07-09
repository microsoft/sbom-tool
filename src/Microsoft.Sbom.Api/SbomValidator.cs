// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using PowerArgs;

namespace Microsoft.Sbom.Api;

public class SbomValidator : ISbomValidator
{
    private readonly IWorkflow<SbomParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow;
    private readonly IRecorder recorder;
    private readonly IEnumerable<ConfigValidator> configValidators;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly IFileSystemUtils fileSystemUtils;

    public SbomValidator(
        IWorkflow<SbomParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow,
        IRecorder recorder,
        IEnumerable<ConfigValidator> configValidators)
    {
        this.sbomParserBasedValidationWorkflow = sbomParserBasedValidationWorkflow ?? throw new ArgumentNullException(nameof(sbomParserBasedValidationWorkflow));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.configValidators = configValidators;
    }

    public SbomValidator(
        IWorkflow<SbomParserBasedValidationWorkflow> sbomParserBasedValidationWorkflow,
        IRecorder recorder,
        IEnumerable<ConfigValidator> configValidators,
        IConfiguration configuration,
        ISbomConfigProvider sbomConfigs,
        IFileSystemUtils fileSystemUtils)
        : this(sbomParserBasedValidationWorkflow, recorder, configValidators)
    {
        this.configuration = configuration;
        this.sbomConfigs = sbomConfigs;
        this.fileSystemUtils = fileSystemUtils;
    }

    public async Task<bool> ValidateSbomAsync()
    {
        var isSuccess = await sbomParserBasedValidationWorkflow.RunAsync();
        await recorder.FinalizeAndLogTelemetryAsync();

        return isSuccess;
    }

    public async Task<SbomValidationResult> ValidateSbomAsync(
        string buildDropPath,
        string outputPath,
        IList<SbomSpecification> specifications,
        string manifestDirPath = null,
        bool validateSignature = false,
        bool ignoreMissing = false,
        string rootPathFilter = null,
        RuntimeConfiguration runtimeConfiguration = null,
        AlgorithmName algorithmName = null)
    {
        // If the API user does not specify a manifest directory path, we will default to the build drop path.
        if (string.IsNullOrWhiteSpace(manifestDirPath))
        {
            manifestDirPath = $"{buildDropPath}\\_manifest";
        }

        var inputConfig = ApiConfigurationBuilder.GetConfiguration(
            buildDropPath,
            outputPath,
            specifications,
            algorithmName,
            manifestDirPath,
            validateSignature,
            ignoreMissing,
            rootPathFilter,
            runtimeConfiguration);

        inputConfig = ValidateConfig(inputConfig);

        inputConfig.ToConfiguration();

        var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo.Value.FirstOrDefault());
        if (!fileSystemUtils.FileExists(sbomConfig.ManifestJsonFilePath))
        {
            throw new FileNotFoundException($"Manifest not found in specified location: {sbomConfig.ManifestJsonFilePath}");
        }

        await sbomParserBasedValidationWorkflow.RunAsync();
        await recorder.FinalizeAndLogTelemetryAsync();

        var errors = recorder.Errors.Select(error => error.ToEntityError()).ToList();
        var hasExceptions = recorder.Exceptions.Any();
        return new SbomValidationResult(!errors.Any() && !hasExceptions, errors);
    }

    private InputConfiguration ValidateConfig(InputConfiguration config)
    {
        foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(config))
        {
            configValidators.ForEach(v =>
            {
                v.CurrentAction = config.ManifestToolAction;
                v.Validate(property.DisplayName, property.GetValue(config), property.Attributes);
            });
        }

        return config;
    }
}
