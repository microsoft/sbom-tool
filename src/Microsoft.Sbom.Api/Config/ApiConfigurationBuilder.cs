// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Serilog.Events;
using Constants = Microsoft.Sbom.Common.Constants;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.ComponentDetection.Detectors.Linux.Contracts;

namespace Microsoft.Sbom.Api.Config
{
    /// <summary>
    /// Builds the configuration object for the SBOM api.
    /// </summary>
    internal class ApiConfigurationBuilder
    {
        /// <summary>
        /// Gets a generate configuration.
        /// </summary>
        /// <param name="rootPath">Path where package exists. If scanning start here.</param>
        /// <param name="manifestDirPath">Output path to where manifest is generated.</param>
        /// <param name="files">Use null to scan.</param>
        /// <param name="packages">Use null to scan.</param>
        /// <param name="metadata"></param>
        /// <param name="specifications"></param>
        /// <param name="runtimeConfiguration"></param>
        /// <param name="verbosity"></param>
        /// <returns>A generate configuration.</returns>
        internal Configuration GetConfiguration(
            string rootPath,
            string manifestDirPath,
            IEnumerable<SBOMFile> files,
            IEnumerable<SBOMPackage> packages,
            SBOMMetadata metadata,
            IList<SBOMSpecification> specifications = null,
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

            RuntimeConfiguration sanitizedRuntimeConfiguration = SanitiseRuntimeConfiguration(runtimeConfiguration);

            var configuration = new Configuration();
            configuration.BuildDropPath = GetConfigurationSetting(rootPath);
            configuration.ManifestDirPath = GetConfigurationSetting(manifestDirPath);
            configuration.ManifestToolAction = ManifestToolActions.Generate;
            configuration.PackageName = GetConfigurationSetting(metadata.PackageName);
            configuration.PackageVersion = GetConfigurationSetting(metadata.PackageVersion);
            configuration.PackageSupplier = GetConfigurationSetting(metadata.PackageSupplier);
            configuration.Parallelism = GetConfigurationSetting(sanitizedRuntimeConfiguration.WorkflowParallelism);
            configuration.GenerationTimestamp = GetConfigurationSetting(sanitizedRuntimeConfiguration.GenerationTimestamp);
            configuration.NamespaceUriBase = GetConfigurationSetting(sanitizedRuntimeConfiguration.NamespaceUriBase);
            configuration.NamespaceUriUniquePart = GetConfigurationSetting(sanitizedRuntimeConfiguration.NamespaceUriUniquePart);
            configuration.FollowSymlinks = GetConfigurationSetting(sanitizedRuntimeConfiguration.FollowSymlinks);
            configuration.DeleteManifestDirIfPresent = GetConfigurationSetting(sanitizedRuntimeConfiguration.DeleteManifestDirectoryIfPresent);

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
                if (specifications.Count == 0)
                {
                    throw new ArgumentException($"'{nameof(specifications)}' must have at least 1 specification.", nameof(specifications));
                }

                IList<ManifestInfo> manifestInfos = specifications
                                                        .Select(s => s.ToManifestInfo())
                                                        .ToList();

                configuration.ManifestInfo = GetConfigurationSetting(manifestInfos);
            }

            return configuration;
        }

        public Configuration GetConfiguration(
            string buildDropPath,
            string outputPath,
            AlgorithmName algorithmName,
            string manifestDirPath,
            string catalogFilePath,
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

            var sanitizedRuntimeConfiguration = SanitiseRuntimeConfiguration(runtimeConfiguration);

            var configuration = new Configuration();
            configuration.BuildDropPath = GetConfigurationSetting(buildDropPath);
            configuration.ManifestDirPath = GetConfigurationSetting(manifestDirPath);
            configuration.ManifestToolAction = ManifestToolActions.Validate;   
            configuration.OutputPath = GetConfigurationSetting(outputPath);
            configuration.HashAlgorithm = GetConfigurationSetting(algorithmName ?? AlgorithmName.SHA256);
            configuration.RootPathFilter = GetConfigurationSetting(rootPathFilter);
            configuration.CatalogFilePath = GetConfigurationSetting(catalogFilePath);
            configuration.ValidateSignature = GetConfigurationSetting(validateSignature);
            configuration.IgnoreMissing = GetConfigurationSetting(ignoreMissing);
            configuration.Parallelism = GetConfigurationSetting(sanitizedRuntimeConfiguration.WorkflowParallelism);
         
            SetVerbosity(sanitizedRuntimeConfiguration, configuration);

            return configuration;
        }

        private void SetVerbosity(RuntimeConfiguration sanitizedRuntimeConfiguration, Configuration configuration)
        {
            switch (sanitizedRuntimeConfiguration.Verbosity)
            {
                case System.Diagnostics.Tracing.EventLevel.Critical:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Fatal);
                    break;
                case System.Diagnostics.Tracing.EventLevel.Informational:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Information);
                    break;
                case System.Diagnostics.Tracing.EventLevel.Error:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Error);
                    break;
                case System.Diagnostics.Tracing.EventLevel.LogAlways:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Verbose);
                    break;
                case System.Diagnostics.Tracing.EventLevel.Warning:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Warning);
                    break;
                case System.Diagnostics.Tracing.EventLevel.Verbose:
                    configuration.Verbosity = GetConfigurationSetting(LogEventLevel.Verbose);
                    break;
                default:
                    configuration.Verbosity = GetConfigurationSetting(Constants.DefaultLogLevel);
                    break;
            }
        }

        private ConfigurationSetting<T> GetConfigurationSetting<T>(T value)
        {
            return new ConfigurationSetting<T>
            {
                Value = value,
                Source = SettingSource.SBOMApi
            };
        }

        private RuntimeConfiguration SanitiseRuntimeConfiguration(RuntimeConfiguration runtimeConfiguration)
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
}
