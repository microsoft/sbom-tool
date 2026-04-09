// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;
using Serilog.Events;
using Constants = Microsoft.Sbom.Common.Constants;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Provides explicit property-by-property mapping methods to convert CLI argument objects
/// and config file objects into <see cref="InputConfiguration"/> instances.
/// </summary>
public static class ConfigurationMapper
{
    public static InputConfiguration MapFrom(GenerationArgs args)
    {
        var s = SettingSource.CommandLine;
        var dest = new InputConfiguration();
        MapCommonArgs(args, dest, s);
        MapGenValAggCommonArgs(args, dest, s);
        MapGenValCommonArgs(args, dest, s);

        dest.BuildDropPath = WrapString(args.BuildDropPath, s);
        dest.BuildComponentPath = WrapString(args.BuildComponentPath, s);
        dest.BuildListFile = WrapString(args.BuildListFile, s);
        dest.ManifestDirPath = WrapString(args.ManifestDirPath, s);
        dest.PackageName = WrapString(args.PackageName, s);
        dest.PackageVersion = WrapString(args.PackageVersion, s);
        dest.PackageSupplier = WrapString(args.PackageSupplier, s);
        dest.DockerImagesToScan = WrapString(args.DockerImagesToScan, s);
        dest.AdditionalComponentDetectorArgs = WrapString(args.AdditionalComponentDetectorArgs, s);
        dest.ExternalDocumentReferenceListFile = WrapString(args.ExternalDocumentReferenceListFile, s);
        dest.NamespaceUriUniquePart = WrapString(args.NamespaceUriUniquePart, s);
        dest.NamespaceUriBase = WrapString(args.NamespaceUriBase, s);
        dest.GenerationTimestamp = WrapString(args.GenerationTimestamp, s);
        dest.DeleteManifestDirIfPresent = WrapNullableBool(args.DeleteManifestDirIfPresent, s);
        dest.FetchLicenseInformation = WrapNullableBool(args.FetchLicenseInformation, s);
        dest.LicenseInformationTimeoutInSeconds = WrapNullableInt(args.LicenseInformationTimeoutInSeconds, s);
        dest.EnablePackageMetadataParsing = WrapNullableBool(args.EnablePackageMetadataParsing, s);

        return dest;
    }

    public static InputConfiguration MapFrom(ValidationArgs args)
    {
        var s = SettingSource.CommandLine;
        var dest = new InputConfiguration();
        MapCommonArgs(args, dest, s);
        MapGenValAggCommonArgs(args, dest, s);
        MapGenValCommonArgs(args, dest, s);

        dest.BuildDropPath = WrapString(args.BuildDropPath, s);
        dest.ManifestDirPath = WrapString(args.ManifestDirPath, s);
        dest.OutputPath = WrapString(args.OutputPath, s);
        dest.ValidateSignature = WrapBool(args.ValidateSignature, s);
        dest.IgnoreMissing = WrapBool(args.IgnoreMissing, s);
        dest.FailIfNoPackages = WrapBool(args.FailIfNoPackages, s);
        dest.RootPathFilter = WrapString(args.RootPathFilter, s);
        dest.HashAlgorithm = WrapAlgorithmName(args.HashAlgorithm, s);
        dest.Conformance = WrapConformance(args.Conformance, s);

#pragma warning disable CS0612 // Type or member is obsolete
        dest.CatalogFilePath = WrapString(args.CatalogFilePath, s);
#pragma warning restore CS0612

        return dest;
    }

    public static InputConfiguration MapFrom(RedactArgs args)
    {
        var s = SettingSource.CommandLine;
        var dest = new InputConfiguration();
        MapCommonArgs(args, dest, s);

        dest.SbomPath = WrapString(args.SbomPath, s);
        dest.SbomDir = WrapString(args.SbomDir, s);
        dest.OutputPath = WrapString(args.OutputPath, s);

        return dest;
    }

    public static InputConfiguration MapFrom(FormatValidationArgs args)
    {
        var s = SettingSource.CommandLine;
        var dest = new InputConfiguration();
        MapCommonArgs(args, dest, s);

        dest.SbomPath = WrapString(args.SbomPath, s);

        return dest;
    }

    public static InputConfiguration MapFrom(AggregationArgs args)
    {
        var s = SettingSource.CommandLine;
        var dest = new InputConfiguration();
        MapCommonArgs(args, dest, s);
        MapGenValAggCommonArgs(args, dest, s);

        return dest;
    }

    public static InputConfiguration MapFrom(ConfigFile config)
    {
        var s = SettingSource.JsonConfig;

#pragma warning disable IDE0017 // Simplify object initialization
        var dest = new InputConfiguration();

        dest.BuildDropPath = WrapString(config.BuildDropPath, s);
        dest.BuildComponentPath = WrapString(config.BuildComponentPath, s);
        dest.BuildListFile = WrapString(config.BuildListFile, s);
        dest.ManifestDirPath = WrapString(config.ManifestDirPath, s);
        dest.OutputPath = WrapString(config.OutputPath, s);
        dest.CatalogFilePath = WrapString(config.CatalogFilePath, s);
        dest.ValidateSignature = WrapNullableBool(config.ValidateSignature, s);
        dest.IgnoreMissing = WrapNullableBool(config.IgnoreMissing, s);
        dest.RootPathFilter = WrapString(config.RootPathFilter, s);
        dest.Verbosity = WrapLogEventLevel(config.Verbosity, s);
        dest.Parallelism = WrapNullableInt(config.Parallelism, s);
        dest.ManifestInfo = WrapManifestInfo(config.ManifestInfo, s);
        dest.HashAlgorithm = WrapAlgorithmName(config.HashAlgorithm, s);
        dest.PackageName = WrapString(config.PackageName, s);
        dest.PackageVersion = WrapString(config.PackageVersion, s);
        dest.PackageSupplier = WrapString(config.PackageSupplier, s);
        dest.ConfigFilePath = WrapString(config.ConfigFilePath, s);
        dest.ManifestToolAction = config.ManifestToolAction;
        dest.TelemetryFilePath = WrapString(config.TelemetryFilePath, s);
        dest.DockerImagesToScan = WrapString(config.DockerImagesToScan, s);
        dest.ExternalDocumentReferenceListFile = WrapString(config.ExternalDocumentReferenceListFile, s);
        dest.AdditionalComponentDetectorArgs = WrapString(config.AdditionalComponentDetectorArgs, s);
        dest.NamespaceUriUniquePart = WrapString(config.NamespaceUriUniquePart, s);
        dest.NamespaceUriBase = WrapString(config.NamespaceUriBase, s);
        dest.GenerationTimestamp = WrapString(config.GenerationTimestamp, s);
        dest.FollowSymlinks = WrapNullableBool(config.FollowSymlinks, s);
        dest.DeleteManifestDirIfPresent = WrapNullableBool(config.DeleteManifestDirIfPresent, s);
        dest.FailIfNoPackages = WrapNullableBool(config.FailIfNoPackages, s);
        dest.FetchLicenseInformation = WrapNullableBool(config.FetchLicenseInformation, s);
        dest.EnablePackageMetadataParsing = WrapNullableBool(config.EnablePackageMetadataParsing, s);
        dest.Conformance = WrapConformance(config.Conformance, s);
        dest.ArtifactInfoMap = WrapArtifactInfoMap(config.ArtifactInfoMap, s);

#pragma warning disable CS0618 // Type or member is obsolete
        dest.ManifestPath = WrapString(config.ManifestPath, s);
#pragma warning restore CS0618
#pragma warning restore IDE0017

        return dest;
    }

    /// <summary>
    /// Merges command-line configuration into config-file configuration.
    /// If the same setting is specified in both with non-default sources, throws.
    /// Then runs post-processing (validation, sanitization, defaults).
    /// </summary>
    public static InputConfiguration Merge(InputConfiguration commandLine, InputConfiguration configFile, ConfigPostProcessor postProcessor)
    {
        configFile.BuildDropPath = MergeSetting(commandLine.BuildDropPath, configFile.BuildDropPath);
        configFile.BuildComponentPath = MergeSetting(commandLine.BuildComponentPath, configFile.BuildComponentPath);
        configFile.BuildListFile = MergeSetting(commandLine.BuildListFile, configFile.BuildListFile);
        configFile.ManifestDirPath = MergeSetting(commandLine.ManifestDirPath, configFile.ManifestDirPath);
        configFile.OutputPath = MergeSetting(commandLine.OutputPath, configFile.OutputPath);
        configFile.Parallelism = MergeSetting(commandLine.Parallelism, configFile.Parallelism);
        configFile.Verbosity = MergeSetting(commandLine.Verbosity, configFile.Verbosity);
        configFile.ConfigFilePath = MergeSetting(commandLine.ConfigFilePath, configFile.ConfigFilePath);
        configFile.ManifestInfo = MergeSetting(commandLine.ManifestInfo, configFile.ManifestInfo);
        configFile.HashAlgorithm = MergeSetting(commandLine.HashAlgorithm, configFile.HashAlgorithm);
        configFile.RootPathFilter = MergeSetting(commandLine.RootPathFilter, configFile.RootPathFilter);
        configFile.CatalogFilePath = MergeSetting(commandLine.CatalogFilePath, configFile.CatalogFilePath);
        configFile.ValidateSignature = MergeSetting(commandLine.ValidateSignature, configFile.ValidateSignature);
        configFile.IgnoreMissing = MergeSetting(commandLine.IgnoreMissing, configFile.IgnoreMissing);
        configFile.PackageName = MergeSetting(commandLine.PackageName, configFile.PackageName);
        configFile.PackageVersion = MergeSetting(commandLine.PackageVersion, configFile.PackageVersion);
        configFile.PackageSupplier = MergeSetting(commandLine.PackageSupplier, configFile.PackageSupplier);
        configFile.FilesList = MergeSetting(commandLine.FilesList, configFile.FilesList);
        configFile.PackagesList = MergeSetting(commandLine.PackagesList, configFile.PackagesList);
        configFile.TelemetryFilePath = MergeSetting(commandLine.TelemetryFilePath, configFile.TelemetryFilePath);
        configFile.DockerImagesToScan = MergeSetting(commandLine.DockerImagesToScan, configFile.DockerImagesToScan);
        configFile.ExternalDocumentReferenceListFile = MergeSetting(commandLine.ExternalDocumentReferenceListFile, configFile.ExternalDocumentReferenceListFile);
        configFile.AdditionalComponentDetectorArgs = MergeSetting(commandLine.AdditionalComponentDetectorArgs, configFile.AdditionalComponentDetectorArgs);
        configFile.NamespaceUriUniquePart = MergeSetting(commandLine.NamespaceUriUniquePart, configFile.NamespaceUriUniquePart);
        configFile.NamespaceUriBase = MergeSetting(commandLine.NamespaceUriBase, configFile.NamespaceUriBase);
        configFile.GenerationTimestamp = MergeSetting(commandLine.GenerationTimestamp, configFile.GenerationTimestamp);
        configFile.FollowSymlinks = MergeSetting(commandLine.FollowSymlinks, configFile.FollowSymlinks);
        configFile.DeleteManifestDirIfPresent = MergeSetting(commandLine.DeleteManifestDirIfPresent, configFile.DeleteManifestDirIfPresent);
        configFile.FailIfNoPackages = MergeSetting(commandLine.FailIfNoPackages, configFile.FailIfNoPackages);
        configFile.FetchLicenseInformation = MergeSetting(commandLine.FetchLicenseInformation, configFile.FetchLicenseInformation);
        configFile.LicenseInformationTimeoutInSeconds = MergeSetting(commandLine.LicenseInformationTimeoutInSeconds, configFile.LicenseInformationTimeoutInSeconds);
        configFile.EnablePackageMetadataParsing = MergeSetting(commandLine.EnablePackageMetadataParsing, configFile.EnablePackageMetadataParsing);
        configFile.SbomPath = MergeSetting(commandLine.SbomPath, configFile.SbomPath);
        configFile.SbomDir = MergeSetting(commandLine.SbomDir, configFile.SbomDir);
        configFile.Conformance = MergeSetting(commandLine.Conformance, configFile.Conformance);
        configFile.ArtifactInfoMap = MergeSetting(commandLine.ArtifactInfoMap, configFile.ArtifactInfoMap);

        // ManifestToolAction is not a ConfigurationSetting — take command-line value if set.
        if (commandLine.ManifestToolAction != default)
        {
            configFile.ManifestToolAction = commandLine.ManifestToolAction;
        }

#pragma warning disable CS0618 // Type or member is obsolete
        configFile.ManifestPath = MergeSetting(commandLine.ManifestPath, configFile.ManifestPath);
#pragma warning restore CS0618

        postProcessor.Process(commandLine, configFile);
        return configFile;
    }

    /// <summary>
    /// Converts a validated <see cref="InputConfiguration"/> to a thread-safe <see cref="Configuration"/>.
    /// </summary>
    public static Configuration ToConfiguration(InputConfiguration src)
    {
#pragma warning disable IDE0017 // Simplify object initialization
        var dest = new Configuration();

        dest.BuildDropPath = src.BuildDropPath;
        dest.BuildComponentPath = src.BuildComponentPath;
        dest.BuildListFile = src.BuildListFile;
        dest.ManifestDirPath = src.ManifestDirPath;
        dest.OutputPath = src.OutputPath;
        dest.Parallelism = src.Parallelism;
        dest.Verbosity = src.Verbosity;
        dest.ConfigFilePath = src.ConfigFilePath;
        dest.ManifestInfo = src.ManifestInfo;
        dest.HashAlgorithm = src.HashAlgorithm;
        dest.RootPathFilter = src.RootPathFilter;
        dest.CatalogFilePath = src.CatalogFilePath;
        dest.ValidateSignature = src.ValidateSignature;
        dest.IgnoreMissing = src.IgnoreMissing;
        dest.ManifestToolAction = src.ManifestToolAction;
        dest.PackageName = src.PackageName;
        dest.PackageVersion = src.PackageVersion;
        dest.PackageSupplier = src.PackageSupplier;
        dest.FilesList = src.FilesList;
        dest.PackagesList = src.PackagesList;
        dest.TelemetryFilePath = src.TelemetryFilePath;
        dest.DockerImagesToScan = src.DockerImagesToScan;
        dest.ExternalDocumentReferenceListFile = src.ExternalDocumentReferenceListFile;
        dest.AdditionalComponentDetectorArgs = src.AdditionalComponentDetectorArgs;
        dest.NamespaceUriUniquePart = src.NamespaceUriUniquePart;
        dest.NamespaceUriBase = src.NamespaceUriBase;
        dest.GenerationTimestamp = src.GenerationTimestamp;
        dest.FollowSymlinks = src.FollowSymlinks;
        dest.DeleteManifestDirIfPresent = src.DeleteManifestDirIfPresent;
        dest.FailIfNoPackages = src.FailIfNoPackages;
        dest.FetchLicenseInformation = src.FetchLicenseInformation;
        dest.LicenseInformationTimeoutInSeconds = src.LicenseInformationTimeoutInSeconds;
        dest.EnablePackageMetadataParsing = src.EnablePackageMetadataParsing;
        dest.SbomPath = src.SbomPath;
        dest.SbomDir = src.SbomDir;
        dest.Conformance = src.Conformance;
        dest.ArtifactInfoMap = src.ArtifactInfoMap;

#pragma warning disable CS0618 // Type or member is obsolete
        dest.ManifestPath = src.ManifestPath;
#pragma warning restore CS0618
#pragma warning restore IDE0017

        return dest;
    }

    // ── Base class mapping helpers ───────────────────────────────────────

    private static void MapCommonArgs(CommonArgs args, InputConfiguration dest, SettingSource s)
    {
        dest.ManifestToolAction = args.ManifestToolAction;
        dest.Verbosity = WrapLogEventLevel(args.Verbosity, s);
    }

    private static void MapGenValAggCommonArgs(GenerationAndValidationAndAggregationCommonArgs args, InputConfiguration dest, SettingSource s)
    {
        dest.ConfigFilePath = WrapString(args.ConfigFilePath, s);
        dest.TelemetryFilePath = WrapString(args.TelemetryFilePath, s);
    }

    private static void MapGenValCommonArgs(GenerationAndValidationCommonArgs args, InputConfiguration dest, SettingSource s)
    {
        dest.Parallelism = WrapNullableInt(args.Parallelism, s);
        dest.FollowSymlinks = WrapNullableBool(args.FollowSymlinks, s);
        dest.ManifestInfo = WrapManifestInfo(args.ManifestInfo, s);
    }

    // ── Merge helper ────────────────────────────────────────────────────

    private static ConfigurationSetting<T> MergeSetting<T>(ConfigurationSetting<T> src, ConfigurationSetting<T> dst)
    {
        if (src != null && dst != null)
        {
            if (src.Source != SettingSource.Default && dst.Source != SettingSource.Default)
            {
                throw new ValidationArgException("Duplicate keys found in config file and command line parameters.");
            }

            return dst.Source == SettingSource.Default ? src : dst;
        }

        return src ?? dst;
    }

    // ── Value wrapping helpers ──────────────────────────────────────────

    private static ConfigurationSetting<string> WrapString(string value, SettingSource source)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        return new ConfigurationSetting<string> { Source = source, Value = value };
    }

    private static ConfigurationSetting<bool> WrapBool(bool value, SettingSource source) =>
        new ConfigurationSetting<bool> { Source = source, Value = value };

    private static ConfigurationSetting<bool> WrapNullableBool(bool? value, SettingSource source)
    {
        if (value == null)
        {
            return null;
        }

        return new ConfigurationSetting<bool> { Source = source, Value = value.Value };
    }

    private static ConfigurationSetting<int> WrapNullableInt(int? value, SettingSource source)
    {
        if (value == null)
        {
            return null;
        }

        return new ConfigurationSetting<int> { Source = source, Value = value.Value };
    }

    private static ConfigurationSetting<LogEventLevel> WrapLogEventLevel(LogEventLevel? value, SettingSource source)
    {
        if (value == null)
        {
            source = SettingSource.Default;
        }

        return new ConfigurationSetting<LogEventLevel>
        {
            Source = source,
            Value = value ?? Constants.DefaultLogLevel
        };
    }

    private static ConfigurationSetting<IList<ManifestInfo>> WrapManifestInfo(IList<ManifestInfo> value, SettingSource source)
    {
        if (value == null)
        {
            source = SettingSource.Default;
        }

        return new ConfigurationSetting<IList<ManifestInfo>>
        {
            Source = source,
            Value = value
        };
    }

    private static ConfigurationSetting<AlgorithmName> WrapAlgorithmName(AlgorithmName value, SettingSource source)
    {
        if (value == null)
        {
            source = SettingSource.Default;
        }

        return new ConfigurationSetting<AlgorithmName>
        {
            Source = source,
            Value = value ?? Api.Utils.Constants.DefaultHashAlgorithmName
        };
    }

    private static ConfigurationSetting<ConformanceType> WrapConformance(ConformanceType value, SettingSource source)
    {
        if (value == null)
        {
            source = SettingSource.Default;
        }

        return new ConfigurationSetting<ConformanceType>
        {
            Source = source,
            Value = value ?? ConformanceType.None
        };
    }

    private static ConfigurationSetting<Dictionary<string, ArtifactInfo>> WrapArtifactInfoMap(Dictionary<string, ArtifactInfo> value, SettingSource source)
    {
        if (value == null || !value.Any())
        {
            return null;
        }

        return new ConfigurationSetting<Dictionary<string, ArtifactInfo>>
        {
            Source = source,
            Value = value
        };
    }
}
