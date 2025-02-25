// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;

namespace Microsoft.Sbom.Api;

/// <summary>
/// Responsible for an API to generate SBOMs.
/// </summary>
public class SbomGenerator : ISBOMGenerator
{
    private readonly IWorkflow<SbomGenerationWorkflow> generationWorkflow;
    private readonly ManifestGeneratorProvider generatorProvider;
    private readonly IRecorder recorder;
    private readonly IEnumerable<ConfigValidator> configValidators;
    private readonly ConfigSanitizer configSanitizer;

    public SbomGenerator(
        IWorkflow<SbomGenerationWorkflow> generationWorkflow,
        ManifestGeneratorProvider generatorProvider,
        IRecorder recorder,
        IEnumerable<ConfigValidator> configValidators,
        ConfigSanitizer configSanitizer)
    {
        this.generationWorkflow = generationWorkflow;
        this.generatorProvider = generatorProvider;
        this.recorder = recorder;
        this.configValidators = configValidators;
        this.configSanitizer = configSanitizer;
    }

    /// <inheritdoc />
    public async Task<SbomGenerationResult> GenerateSbomAsync(
        string rootPath,
        string componentPath,
        SBOMMetadata metadata,
        IList<SbomSpecification> specifications = null,
        RuntimeConfiguration runtimeConfiguration = null,
        string manifestDirPath = null,
        string externalDocumentReferenceListFile = null)
    {
        // Get scan configuration
        var inputConfiguration = ApiConfigurationBuilder.GetConfiguration(
            rootPath,
            manifestDirPath,
            null,
            null,
            metadata,
            specifications,
            runtimeConfiguration,
            externalDocumentReferenceListFile,
            componentPath);

        // Validate the configuration
        inputConfiguration = ValidateConfig(inputConfiguration);

        // Globally update the configuration
        inputConfiguration.ToConfiguration();

        // This is the generate workflow
        var isSuccess = await generationWorkflow.RunAsync();

        await recorder.FinalizeAndLogTelemetryAsync();

        var entityErrors = recorder.Errors.Select(error => error.ToEntityError()).ToList();

        return new SbomGenerationResult(isSuccess, entityErrors);
    }

    /// <inheritdoc />
    public async Task<SbomGenerationResult> GenerateSbomAsync(
        string rootPath,
        IEnumerable<SbomFile> files,
        IEnumerable<SbomPackage> packages,
        SBOMMetadata metadata,
        IList<SbomSpecification> specifications = null,
        RuntimeConfiguration runtimeConfiguration = null,
        string manifestDirPath = null,
        string externalDocumentReferenceListFile = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException($"'{nameof(rootPath)}' cannot be null or whitespace.", nameof(rootPath));
        }

        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(packages);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(manifestDirPath);

        var inputConfiguration = ApiConfigurationBuilder.GetConfiguration(
            rootPath,
            manifestDirPath,
            files,
            packages,
            metadata,
            specifications,
            runtimeConfiguration,
            externalDocumentReferenceListFile);
        inputConfiguration = ValidateConfig(inputConfiguration);

        inputConfiguration.ToConfiguration();

        // This is the generate workflow
        var result = await generationWorkflow.RunAsync();

        return new SbomGenerationResult(result, new List<EntityError>());
    }

    /// <inheritdoc />
    public IEnumerable<AlgorithmName> GetRequiredAlgorithms(SbomSpecification specification)
    {
        ArgumentNullException.ThrowIfNull(specification);

        // The provider will throw if the generator is not found.
        var generator = generatorProvider.Get(specification.ToManifestInfo());

        return generator
            .RequiredHashAlgorithms
            .ToList();
    }

    public IEnumerable<SbomSpecification> GetSupportedSBOMSpecifications() => generatorProvider
        .GetSupportedManifestInfos()
        .Select(ManifestInfo.ToSBOMSpecification)
        .ToList();

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

        configSanitizer.SanitizeConfig(config);
        return config;
    }
}
