// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Serilog.Events;
using ApiConstants = Microsoft.Sbom.Api.Utils.Constants;
using Constants = Microsoft.Sbom.Common.Constants;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Builds the configuration object for the SBOM api.
/// </summary>
public static class ApiConfigurationBuilder
{
    /// <summary>
    /// Gets a generate configuration.
    /// </summary>
    /// <param name="rootPath">Path where package exists. If scanning start here.</param>
    /// <param name="manifestDirPath">Output path to where manifest is generated.</param>
    /// <param name="files">Use null to scan all files.</param>
    /// <param name="packages">Use null to scan all packages.</param>
    /// <param name="metadata"></param>
    /// <param name="specifications"></param>
    /// <param name="runtimeConfiguration"></param>
    /// <param name="verbosity"></param>
    /// <returns>A generate configuration.</returns>
    public static InputConfiguration GetConfiguration(
        string rootPath,
        string manifestDirPath,
        IEnumerable<SbomFile> files,
        IEnumerable<SbomPackage> packages,
        SBOMMetadata metadata,
        IList<SbomSpecification> specifications = null,
        RuntimeConfiguration runtimeConfiguration = null,
        string externalDocumentReferenceListFile = null,
        string componentPath = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException($"'{nameof(rootPath)}' cannot be null or whitespace.", nameof(rootPath));
        }

        if (metadata is null)
        {
            throw new ArgumentNullException(nameof(metadata));
        }

        var sanitizedRuntimeConfiguration = SanitiseRuntimeConfiguration(runtimeConfiguration);

        var configuration = new InputConfiguration
        {
            BuildDropPath = GetConfigurationSetting(rootPath),
            ManifestDirPath = GetConfigurationSetting(manifestDirPath),
            ManifestToolAction = ManifestToolActions.Generate,
            PackageName = GetConfigurationSetting(metadata.PackageName),
            PackageVersion = GetConfigurationSetting(metadata.PackageVersion),
            PackageSupplier = GetConfigurationSetting(metadata.PackageSupplier),
            Parallelism = GetConfigurationSetting(sanitizedRuntimeConfiguration.WorkflowParallelism),
            GenerationTimestamp = GetConfigurationSetting(sanitizedRuntimeConfiguration.GenerationTimestamp),
            NamespaceUriBase = GetConfigurationSetting(sanitizedRuntimeConfiguration.NamespaceUriBase),
            NamespaceUriUniquePart = GetConfigurationSetting(sanitizedRuntimeConfiguration.NamespaceUriUniquePart),
            FollowSymlinks = GetConfigurationSetting(sanitizedRuntimeConfiguration.FollowSymlinks),
            DeleteManifestDirIfPresent = GetConfigurationSetting(sanitizedRuntimeConfiguration.DeleteManifestDirectoryIfPresent),
        };

        SetVerbosity(sanitizedRuntimeConfiguration, configuration);

        if (packages != null)
        {
            configuration.PackagesList = GetConfigurationSetting(packages);
        }

        if (files != null)
        {
            configuration.FilesList = GetConfigurationSetting(files);
        }

        if (externalDocumentReferenceListFile != null)
        {
            configuration.ExternalDocumentReferenceListFile = GetConfigurationSetting(externalDocumentReferenceListFile);
        }

        if (!string.IsNullOrWhiteSpace(componentPath))
        {
            configuration.BuildComponentPath = GetConfigurationSetting(componentPath);
        }

        // Convert sbom specifications to manifest info.
        if (specifications != null)
        {
            configuration.ManifestInfo = ConvertSbomSpecificationToManifestInfo(specifications);
        }

        return configuration;
    }

    public static InputConfiguration GetConfiguration(
        string buildDropPath,
        string outputPath,
        IList<SbomSpecification> specifications,
        AlgorithmName algorithmName,
        string manifestDirPath,
        bool validateSignature,
        bool ignoreMissing,
        string rootPathFilter,
        RuntimeConfiguration runtimeConfiguration)
    {
        if (string.IsNullOrWhiteSpace(buildDropPath))
        {
            throw new ArgumentException($"'{nameof(buildDropPath)}' cannot be null or whitespace.", nameof(buildDropPath));
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            throw new ArgumentException($"'{nameof(outputPath)}' cannot be null or whitespace.", nameof(outputPath));
        }

        if (specifications is null || specifications.Count == 0)
        {
            specifications = new List<SbomSpecification>() { ApiConstants.SPDX22Specification };
        }

        var sanitizedRuntimeConfiguration = SanitiseRuntimeConfiguration(runtimeConfiguration);

        var configuration = new InputConfiguration
        {
            BuildDropPath = GetConfigurationSetting(buildDropPath),
            ManifestDirPath = GetConfigurationSetting(manifestDirPath),
            ManifestToolAction = ManifestToolActions.Validate,
            OutputPath = GetConfigurationSetting(outputPath),
            HashAlgorithm = GetConfigurationSetting(algorithmName ?? AlgorithmName.SHA256),
            RootPathFilter = GetConfigurationSetting(rootPathFilter),
            ValidateSignature = GetConfigurationSetting(validateSignature),
            IgnoreMissing = GetConfigurationSetting(ignoreMissing),
            Parallelism = GetConfigurationSetting(sanitizedRuntimeConfiguration.WorkflowParallelism),
            ManifestInfo = ConvertSbomSpecificationToManifestInfo(specifications),
        };

        SetVerbosity(sanitizedRuntimeConfiguration, configuration);

        return configuration;
    }

    /// <summary>
    /// Convert sbom specifications to manifest info.
    /// </summary>
    /// <param name="specifications"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    private static ConfigurationSetting<IList<ManifestInfo>> ConvertSbomSpecificationToManifestInfo(IList<SbomSpecification> specifications)
    {
        if (specifications is null)
        {
            throw new ArgumentNullException(nameof(specifications));
        }

        if (specifications.Count == 0)
        {
            throw new ArgumentException($"'{nameof(specifications)}' must have at least 1 specification.", nameof(specifications));
        }

        IList<ManifestInfo> manifestInfos = specifications
            .Select(s => s.ToManifestInfo())
            .ToList();

        return GetConfigurationSetting(manifestInfos);
    }

    private static void SetVerbosity(RuntimeConfiguration sanitizedRuntimeConfiguration, InputConfiguration configuration)
    {
        configuration.Verbosity = sanitizedRuntimeConfiguration.Verbosity switch
        {
            System.Diagnostics.Tracing.EventLevel.Critical => GetConfigurationSetting(LogEventLevel.Fatal),
            System.Diagnostics.Tracing.EventLevel.Informational => GetConfigurationSetting(LogEventLevel.Information),
            System.Diagnostics.Tracing.EventLevel.Error => GetConfigurationSetting(LogEventLevel.Error),
            System.Diagnostics.Tracing.EventLevel.LogAlways => GetConfigurationSetting(LogEventLevel.Verbose),
            System.Diagnostics.Tracing.EventLevel.Warning => GetConfigurationSetting(LogEventLevel.Warning),
            System.Diagnostics.Tracing.EventLevel.Verbose => GetConfigurationSetting(LogEventLevel.Verbose),
            _ => GetConfigurationSetting(Constants.DefaultLogLevel),
        };
    }

    private static ConfigurationSetting<T> GetConfigurationSetting<T>(T value)
    {
        return new ConfigurationSetting<T>
        {
            Value = value,
            Source = SettingSource.SBOMApi
        };
    }

    private static RuntimeConfiguration SanitiseRuntimeConfiguration(RuntimeConfiguration runtimeConfiguration)
    {
        if (runtimeConfiguration == null)
        {
            runtimeConfiguration = new RuntimeConfiguration
            {
                WorkflowParallelism = Constants.DefaultParallelism,
                Verbosity = System.Diagnostics.Tracing.EventLevel.Warning,
                DeleteManifestDirectoryIfPresent = false,
                FollowSymlinks = true
            };
        }

        if (runtimeConfiguration.WorkflowParallelism < Constants.MinParallelism
            || runtimeConfiguration.WorkflowParallelism > Constants.MaxParallelism)
        {
            runtimeConfiguration.WorkflowParallelism = Constants.DefaultParallelism;
        }

        return runtimeConfiguration;
    }
}
