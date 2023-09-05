// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Serilog.Events;

namespace Microsoft.Sbom.Common.Config;

[SuppressMessage("StyleCop.CSharp.NamingRules", "SA1311:Static readonly fields should begin with upper-case letter", Justification = "Private fields with the same name as public properties.")]
[SuppressMessage("Naming", "CA1724:Type names should not match namespaces", Justification = "This is the configuration class")]
public class Configuration : IConfiguration
{
    private static readonly AsyncLocal<ConfigurationSetting<string>> buildDropPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> buildComponentPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> buildListFile = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> manifestDirPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> manifestPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> outputPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<int>> parallelism = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> configFilePath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<IList<ManifestInfo>>> manifestInfo = new ();
    private static readonly AsyncLocal<ConfigurationSetting<AlgorithmName>> hashAlgorithm = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> rootFilterPath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> catalogFilePath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> validateSignature = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> ignoreMissing = new ();
    private static readonly AsyncLocal<ManifestToolActions> manifestToolAction = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> packageName = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> packageVersion = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> packageSupplier = new ();
    private static readonly AsyncLocal<ConfigurationSetting<IEnumerable<SbomFile>>> filesList = new ();
    private static readonly AsyncLocal<ConfigurationSetting<IEnumerable<SbomPackage>>> packagesList = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> telemetryFilePath = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> dockerImagesToScan = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> externalDocumentReferenceListFile = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> additionalComponentDetectorArgs = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> namespaceUriUniquePart = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> namespaceUriBase = new ();
    private static readonly AsyncLocal<ConfigurationSetting<string>> generationTimestamp = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> followSymlinks = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> deleteManifestDirIfPresent = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> failIfNoPackages = new ();
    private static readonly AsyncLocal<ConfigurationSetting<bool>> fetchLicenseInformation = new ();
    private static readonly AsyncLocal<ConfigurationSetting<LogEventLevel>> verbosity = new ();

    /// <inheritdoc cref="IConfiguration.BuildDropPath" />
    [DirectoryExists]
    [DirectoryPathIsWritable(ForAction = ManifestToolActions.Generate)]
    [ValueRequired]
    [Path]
    public ConfigurationSetting<string> BuildDropPath
    {
        get => buildDropPath.Value;
        set => buildDropPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.BuildComponentPath" />
    [DirectoryExists]
    [Path]
    public ConfigurationSetting<string> BuildComponentPath
    {
        get => buildComponentPath.Value;
        set => buildComponentPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.BuildListFile" />
    [FileExists]
    public ConfigurationSetting<string> BuildListFile
    {
        get => buildListFile.Value;
        set => buildListFile.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ManifestPath" />
    [Obsolete("This field is not provided by the user or configFile, set by system")]
    [Path]
    public ConfigurationSetting<string> ManifestPath
    {
        get => manifestPath.Value;
        set => manifestPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ManifestDirPath" />
    [DirectoryExists]
    [DirectoryPathIsWritable(ForAction = ManifestToolActions.Generate)]
    [Path]
    public ConfigurationSetting<string> ManifestDirPath
    {
        get => manifestDirPath.Value;
        set => manifestDirPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.OutputPath" />
    [FilePathIsWritable]
    [ValueRequired(ForAction = ManifestToolActions.Validate)]
    [Path]
    public ConfigurationSetting<string> OutputPath
    {
        get => outputPath.Value;
        set => outputPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.Parallelism" />
    [IntRange(minRange: Constants.MinParallelism, maxRange: Constants.MaxParallelism)]
    [DefaultValue(Constants.DefaultParallelism)]
    public ConfigurationSetting<int> Parallelism
    {
        get => parallelism.Value;
        set => parallelism.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.Verbosity" />
    public ConfigurationSetting<LogEventLevel> Verbosity
    {
        get => verbosity.Value;
        set => verbosity.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ConfigFilePath" />
    [Path]
    public ConfigurationSetting<string> ConfigFilePath
    {
        get => configFilePath.Value;
        set => configFilePath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ManifestInfo" />
    public ConfigurationSetting<IList<ManifestInfo>> ManifestInfo
    {
        get => manifestInfo.Value;
        set => manifestInfo.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.HashAlgorithm" />
    public ConfigurationSetting<AlgorithmName> HashAlgorithm
    {
        get => hashAlgorithm.Value;
        set => hashAlgorithm.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.RootPathFilter" />
    [Path]
    public ConfigurationSetting<string> RootPathFilter
    {
        get => rootFilterPath.Value;
        set => rootFilterPath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.CatalogFilePath" />
    [Path]
    public ConfigurationSetting<string> CatalogFilePath
    {
        get => catalogFilePath.Value;
        set => catalogFilePath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ValidateSignature" />
    [DefaultValue(false)]
    public ConfigurationSetting<bool> ValidateSignature
    {
        get => validateSignature.Value;
        set => validateSignature.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.IgnoreMissing" />
    [DefaultValue(false)]
    public ConfigurationSetting<bool> IgnoreMissing
    {
        get => ignoreMissing.Value;
        set => ignoreMissing.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ManifestToolAction" />
    public ManifestToolActions ManifestToolAction
    {
        get => manifestToolAction.Value;
        set => manifestToolAction.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.PackageName" />
    public ConfigurationSetting<string> PackageName 
    {
        get => packageName.Value;
        set => packageName.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.PackageVersion" />
    public ConfigurationSetting<string> PackageVersion
    {
        get => packageVersion.Value;
        set => packageVersion.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.PackageSupplier" />
    [ValueRequired(ForAction = ManifestToolActions.Generate)]
    public ConfigurationSetting<string> PackageSupplier
    {
        get => packageSupplier.Value;
        set => packageSupplier.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.FilesList" />
    public ConfigurationSetting<IEnumerable<SbomFile>> FilesList
    {
        get => filesList.Value;
        set => filesList.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.PackagesList" />
    public ConfigurationSetting<IEnumerable<SbomPackage>> PackagesList
    {
        get => packagesList.Value;
        set => packagesList.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.TelemetryFilePath" />
    [Path]
    public ConfigurationSetting<string> TelemetryFilePath
    {
        get => telemetryFilePath.Value;
        set => telemetryFilePath.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.DockerImagesToScan" />
    public ConfigurationSetting<string> DockerImagesToScan
    {
        get => dockerImagesToScan.Value;
        set => dockerImagesToScan.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.ExternalDocumentReferenceListFile" />
    [FileExists]
    public ConfigurationSetting<string> ExternalDocumentReferenceListFile
    {
        get => externalDocumentReferenceListFile.Value;
        set => externalDocumentReferenceListFile.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.AdditionalComponentDetectorArgs" />
    public ConfigurationSetting<string> AdditionalComponentDetectorArgs
    {
        get => additionalComponentDetectorArgs.Value;
        set => additionalComponentDetectorArgs.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.NamespaceUriUniquePart" />
    public ConfigurationSetting<string> NamespaceUriUniquePart
    {
        get => namespaceUriUniquePart.Value;
        set => namespaceUriUniquePart.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.NamespaceUriBase" />
    [ValidUri(ForAction = ManifestToolActions.Generate, UriKind = UriKind.Absolute)]
    [ValueRequired(ForAction = ManifestToolActions.Generate)]
    public ConfigurationSetting<string> NamespaceUriBase
    {
        get => namespaceUriBase.Value;
        set => namespaceUriBase.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.GenerationTimestamp" />
    public ConfigurationSetting<string> GenerationTimestamp
    {
        get => generationTimestamp.Value;
        set => generationTimestamp.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.FollowSymlinks" />
    [DefaultValue(true)]
    public ConfigurationSetting<bool> FollowSymlinks
    {
        get => followSymlinks.Value;
        set => followSymlinks.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.DeleteManifestDirIfPresent" />
    [DefaultValue(false)]
    public ConfigurationSetting<bool> DeleteManifestDirIfPresent
    {
        get => deleteManifestDirIfPresent.Value;
        set => deleteManifestDirIfPresent.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.FailIfNoPackages" />
    [DefaultValue(false)]
    public ConfigurationSetting<bool> FailIfNoPackages
    {
        get => failIfNoPackages.Value;
        set => failIfNoPackages.Value = value;
    }

    /// <inheritdoc cref="IConfiguration.FetchLicenseInformation" />
    [DefaultValue(false)]
    public ConfigurationSetting<bool> FetchLicenseInformation
    {
        get => fetchLicenseInformation.Value;
        set => fetchLicenseInformation.Value = value;
    }
}