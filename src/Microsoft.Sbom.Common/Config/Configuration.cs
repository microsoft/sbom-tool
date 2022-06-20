// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using ManifestInterface.Entities;
using Microsoft.Sbom.Api.Attributes;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Microsoft.Sbom.Common.Config
{
    public class Configuration : IConfiguration
    {
        /// <inheritdoc cref="IConfiguration.BuildDropPath" />
        [DirectoryExists]
        [DirectoryPathIsWritable(ForAction = ManifestToolActions.Generate)]
        [ValueRequired]
        public ConfigurationSetting<string> BuildDropPath { get; set; }

        /// <inheritdoc cref="IConfiguration.BuildComponentPath" />
        [DirectoryExists]
        public ConfigurationSetting<string> BuildComponentPath { get; set; }

        /// <inheritdoc cref="IConfiguration.BuildListFile" />
        [FileExists]
        public ConfigurationSetting<string> BuildListFile { get; set; }

        /// <inheritdoc cref="IConfiguration.ManifestPath" />
        [Obsolete("This field is not provided by the user or configFile, set by system")]
        public ConfigurationSetting<string> ManifestPath { get; set; }

        /// <inheritdoc cref="IConfiguration.ManifestDirPath" />
        [DirectoryExists]
        [DirectoryPathIsWritable(ForAction = ManifestToolActions.Generate)]
        public ConfigurationSetting<string> ManifestDirPath { get; set; }

        /// <inheritdoc cref="IConfiguration.OutputPath" />
        [FilePathIsWritable]
        [ValueRequired(ForAction = ManifestToolActions.Validate)]
        public ConfigurationSetting<string> OutputPath { get; set; }

        /// <inheritdoc cref="IConfiguration.Parallelism" />
        [IntRange(minRange: Constants.MinParallelism, maxRange: Constants.MaxParallelism)]
        [DefaultValue(Constants.DefaultParallelism)]
        public ConfigurationSetting<int> Parallelism { get; set; }

        /// <inheritdoc cref="IConfiguration.Verbosity" />
        public ConfigurationSetting<LogEventLevel> Verbosity { get; set; }

        /// <inheritdoc cref="IConfiguration.ConfigFilePath" />
        public ConfigurationSetting<string> ConfigFilePath { get; set; }

        /// <inheritdoc cref="IConfiguration.ManifestInfo" />
        public ConfigurationSetting<IList<ManifestInfo>> ManifestInfo { get; set; }

        /// <inheritdoc cref="IConfiguration.HashAlgorithm" />
        public ConfigurationSetting<AlgorithmName> HashAlgorithm { get; set; }

        /// <inheritdoc cref="IConfiguration.RootPathFilter" />
        public ConfigurationSetting<string> RootPathFilter { get; set; }

        /// <inheritdoc cref="IConfiguration.CatalogFilePath" />
        public ConfigurationSetting<string> CatalogFilePath { get; set; }

        /// <inheritdoc cref="IConfiguration.ValidateSignature" />
        [DefaultValue(false)]
        public ConfigurationSetting<bool> ValidateSignature { get; set; }

        /// <inheritdoc cref="IConfiguration.IgnoreMissing" />
        [DefaultValue(false)]
        public ConfigurationSetting<bool> IgnoreMissing { get; set; }

        /// <inheritdoc cref="IConfiguration.ManifestToolAction" />
        public ManifestToolActions ManifestToolAction { get; set; }

        /// <inheritdoc cref="IConfiguration.PackageName" />
        public ConfigurationSetting<string> PackageName { get; set; }

        /// <inheritdoc cref="IConfiguration.PackageVersion" />
        public ConfigurationSetting<string> PackageVersion { get; set; }

        /// <inheritdoc cref="IConfiguration.FilesList" />
        public ConfigurationSetting<IEnumerable<SBOMFile>> FilesList { get; set; }

        /// <inheritdoc cref="IConfiguration.PackagesList" />
        public ConfigurationSetting<IEnumerable<SBOMPackage>> PackagesList { get; set; }

        /// <inheritdoc cref="IConfiguration.TelemetryFilePath" />
        public ConfigurationSetting<string> TelemetryFilePath { get; set; }

        /// <inheritdoc cref="IConfiguration.DockerImagesToScan" />
        public ConfigurationSetting<string> DockerImagesToScan { get; set; }

        /// <inheritdoc cref="IConfiguration.ExternalDocumentReferenceListFile" />
        [FileExists]
        public ConfigurationSetting<string> ExternalDocumentReferenceListFile { get; set; }

        /// <inheritdoc cref="IConfiguration.AdditionalComponentDetectorArgs" />
        public ConfigurationSetting<string> AdditionalComponentDetectorArgs { get; set; }

        /// <inheritdoc cref="IConfiguration.NamespaceUriUniquePart" />
        public ConfigurationSetting<string> NamespaceUriUniquePart { get; set; }

        /// <inheritdoc cref="IConfiguration.NamespaceUriBase" />
        [ValidUri(ForAction = ManifestToolActions.Generate, UriKind = UriKind.Absolute)]
        [ValueRequired(ForAction = ManifestToolActions.Generate)]
        public ConfigurationSetting<string> NamespaceUriBase { get; set; }

        /// <inheritdoc cref="IConfiguration.GenerationTimestamp" />
        public ConfigurationSetting<string> GenerationTimestamp { get; set; }

        /// <inheritdoc cref="IConfiguration.FollowSymlinks" />
        [DefaultValue(true)]
        public ConfigurationSetting<bool> FollowSymlinks { get; set; }
    }
}
