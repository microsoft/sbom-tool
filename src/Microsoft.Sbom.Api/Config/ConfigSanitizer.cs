// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;
using Serilog;
using Serilog.Core;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Sanitizes a validated configuration by setting additional parameters or fixing default parameters if needed.
/// </summary>
public class ConfigSanitizer
{
    private readonly IHashAlgorithmProvider hashAlgorithmProvider;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IAssemblyConfig assemblyConfig;

    internal static string SbomToolVersion => VersionValue.Value;

    private static readonly Lazy<string> VersionValue = new Lazy<string>(() => typeof(SbomToolCmdRunner).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty);

    public ConfigSanitizer(IHashAlgorithmProvider hashAlgorithmProvider, IFileSystemUtils fileSystemUtils, IAssemblyConfig assemblyConfig)
    {
        this.hashAlgorithmProvider = hashAlgorithmProvider ?? throw new ArgumentNullException(nameof(hashAlgorithmProvider));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.assemblyConfig = assemblyConfig ?? throw new ArgumentNullException(nameof(assemblyConfig));
    }

    public IConfiguration SanitizeConfig(IConfiguration configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        // Create temporary logger to show logs during config sanitizing
        var logger = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = configuration.Verbosity.Value })
            .WriteTo.Console(outputTemplate: Constants.LoggerTemplate)
            .CreateLogger();

        // If BuildDropPath is null then run the logic to check whether it is required or not based on the current configuration.
        if ((configuration.ManifestToolAction == ManifestToolActions.Validate || configuration.ManifestToolAction == ManifestToolActions.Generate) &&
            (configuration.BuildDropPath?.Value == null || (configuration.DockerImagesToScan?.Value != null && configuration.BuildComponentPath?.Value == null)))
        {
            ValidateBuildDropPathConfiguration(configuration);
            configuration.BuildDropPath = GetTempBuildDropPath(configuration);
        }

        CheckValidateFormatConfig(configuration);

        configuration.HashAlgorithm = GetHashAlgorithmName(configuration);

        // set ManifestDirPath after validation of DirectoryExist and DirectoryPathIsWritable, this wouldn't exist because it needs to be created by the tool.
        configuration.ManifestDirPath = GetManifestDirPath(configuration.ManifestDirPath, configuration.BuildDropPath?.Value, configuration.ManifestToolAction);

        // Set namespace value, this handles default values and user provided values.
        if (configuration.ManifestToolAction == ManifestToolActions.Generate || configuration.ManifestToolAction == ManifestToolActions.Aggregate)
        {
            configuration.NamespaceUriBase = GetNamespaceBaseUri(configuration, logger);
        }

        // Set default ManifestInfo for generation in case user doesn't provide a value.
        configuration.ManifestInfo = GetDefaultManifestInfoForGenerationAction(configuration);

        // Set default ManifestInfo for validation in case user doesn't provide a value.
        configuration.ManifestInfo = GetDefaultManifestInfoForValidationAction(configuration);

        // Set default package supplier if not provided in configuration.
        configuration.PackageSupplier = GetPackageSupplierFromAssembly(configuration, logger);

        configuration.Conformance = GetConformance(configuration);

        // Prevent null value for LicenseInformationTimeoutInSeconds.
        // Values of (0, Constants.MaxLicenseFetchTimeoutInSeconds] are allowed. Negative values are replaced with the default, and
        // the higher values are truncated to the maximum of Common.Constants.MaxLicenseFetchTimeoutInSeconds
        if (configuration.LicenseInformationTimeoutInSeconds is null)
        {
            configuration.LicenseInformationTimeoutInSeconds = new(Common.Constants.DefaultLicenseFetchTimeoutInSeconds, SettingSource.Default);
        }
        else if (configuration.LicenseInformationTimeoutInSeconds.Value <= 0)
        {
            logger.Warning($"Negative and Zero Values not allowed for timeout. Using the default {Common.Constants.DefaultLicenseFetchTimeoutInSeconds} seconds instead.");
            configuration.LicenseInformationTimeoutInSeconds.Value = Common.Constants.DefaultLicenseFetchTimeoutInSeconds;
        }
        else if (configuration.LicenseInformationTimeoutInSeconds.Value > Common.Constants.MaxLicenseFetchTimeoutInSeconds)
        {
            logger.Warning($"Specified timeout exceeds maximum allowed. Truncating the timeout to {Common.Constants.MaxLicenseFetchTimeoutInSeconds} seconds.");
            configuration.LicenseInformationTimeoutInSeconds.Value = Common.Constants.MaxLicenseFetchTimeoutInSeconds;
        }

        // Check if arg -lto is specified but -li is not
        if (configuration.FetchLicenseInformation?.Value != true && !configuration.LicenseInformationTimeoutInSeconds.IsDefaultSource)
        {
            logger.Warning("A license fetching timeout is specified (argument -lto), but this has no effect when FetchLicenseInfo is unspecified or false (argument -li)");
        }

        // Replace backslashes in directory paths with the OS-sepcific directory separator character.
        PathUtils.ConvertToOSSpecificPathSeparators(configuration);

        CheckAggregationConfig(configuration);

        logger.Dispose();

        return configuration;
    }

    private void CheckValidateFormatConfig(IConfiguration config)
    {
        if (config.ManifestToolAction != ManifestToolActions.ValidateFormat)
        {
            return;
        }

        if (config.SbomPath?.Value == null)
        {
            throw new ValidationArgException("Please provide a value for the SbomPath (-sp) parameter to validate the SBOM.");
        }
    }

    private void CheckAggregationConfig(IConfiguration config)
    {
        if (config.ManifestToolAction != ManifestToolActions.Aggregate)
        {
            return;
        }

        if (config.ArtifactInfoMap?.Value == null || !config.ArtifactInfoMap.Value.Any())
        {
            throw new ValidationArgException("Please provide a value for the ArtifactInfoMap to aggregate the SBOMs.");
        }
    }

    private ConfigurationSetting<IList<ManifestInfo>> GetDefaultManifestInfoForValidationAction(IConfiguration configuration)
    {
        if (configuration.ManifestToolAction != ManifestToolActions.Validate
            || (configuration.ManifestInfo?.Value != null && configuration.ManifestInfo?.Value?.Count != 0))
        {
            return configuration.ManifestInfo;
        }

        var defaultManifestInfo = assemblyConfig.DefaultManifestInfoForValidationAction;
        if (defaultManifestInfo == null && (configuration.ManifestInfo.Value == null || configuration.ManifestInfo.Value.Count == 0))
        {
            throw new ValidationArgException("Please provide a value for the ManifestInfo (-mi) parameter to validate the SBOM.");
        }

        return new ConfigurationSetting<IList<ManifestInfo>>
        {
            Source = SettingSource.Default,
            Value = new List<ManifestInfo>()
            {
                defaultManifestInfo
            }
        };
    }

    private ConfigurationSetting<IList<ManifestInfo>> GetDefaultManifestInfoForGenerationAction(IConfiguration configuration)
    {
        if (configuration.ManifestToolAction != ManifestToolActions.Generate)
        {
            return configuration.ManifestInfo;
        }

        if (configuration.ManifestInfo?.Value != null && configuration.ManifestInfo.Value.Count != 0)
        {
            return configuration.ManifestInfo;
        }

        // Use default ManifestInfo for generation if none is given.
        var defaultManifestInfo = assemblyConfig.DefaultManifestInfoForGenerationAction;
        return new ConfigurationSetting<IList<ManifestInfo>>
        {
            Source = SettingSource.Default,
            Value = new List<ManifestInfo> { defaultManifestInfo }
        };
    }

    private void ValidateBuildDropPathConfiguration(IConfiguration configuration)
    {
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            if (configuration.ManifestDirPath?.Value != null && configuration.DockerImagesToScan?.Value != null)
            {
                return;
            }
            else if (configuration.ManifestDirPath?.Value == null && configuration.BuildComponentPath?.Value == null && configuration.DockerImagesToScan?.Value != null)
            {
                throw new ValidationArgException("Please provide a (-m) if you intend to create an SBOM with only the contents of the Docker image or a (-bc) if you intend to include other components in your SBOM.");
            }
            else if (configuration.ManifestDirPath?.Value == null && configuration.DockerImagesToScan?.Value != null)
            {
                throw new ValidationArgException("Please provide a value for the ManifestDirPath (-m) parameter to generate the SBOM for the specified Docker image.");
            }
            else
            {
                throw new ValidationArgException("Please provide a value for the BuildDropPath (-b) parameter to generate the SBOM.");
            }
        }
        else
        {
            throw new ValidationArgException("Please provide a value for the BuildDropPath (-b) parameter.");
        }
    }

    private ConfigurationSetting<string> GetTempBuildDropPath(IConfiguration configuration)
    {
        return new ConfigurationSetting<string>
        {
            Source = SettingSource.Default,
            Value = fileSystemUtils.GetSbomToolTempPath(),
        };
    }

    private ConfigurationSetting<AlgorithmName> GetHashAlgorithmName(IConfiguration configuration)
    {
        if (configuration.ManifestToolAction != ManifestToolActions.Validate)
        {
            return configuration.HashAlgorithm;
        }

        // Convert to actual hash algorithm values.
        var oldValue = configuration.HashAlgorithm;
        var newValue = hashAlgorithmProvider.Get(oldValue?.Value?.Name);

        return new ConfigurationSetting<AlgorithmName>
        {
            Source = oldValue.Source,
            Value = newValue
        };
    }

    private ConfigurationSetting<ConformanceType> GetConformance(IConfiguration configuration)
    {
        // Convert to Conformance enum value.
        var oldValue = configuration.Conformance;
        var newValue = ConformanceType.FromString(oldValue?.Value?.ToString());

        // Conformance is only supported for ManifestInfo value of SPDX 3.0 and above.
        if (!newValue.Equals(ConformanceType.None) && !configuration.ManifestInfo.Value.Any(mi => mi.Equals(Constants.SPDX30ManifestInfo)))
        {
            throw new ValidationArgException($"Conformance {newValue.Name} is not supported with ManifestInfo value of {configuration.ManifestInfo.Value.First()}." +
                $"Please use a supported combination.");
        }
        else
        {
            return new ConfigurationSetting<ConformanceType>
            {
                Source = oldValue != null ? oldValue.Source : SettingSource.Default,
                Value = newValue
            };
        }
    }

    private ConfigurationSetting<string> GetNamespaceBaseUri(IConfiguration configuration, ILogger logger)
    {
        // If assembly name is not defined but a namespace was provided, then return the current value.
        if (string.IsNullOrWhiteSpace(assemblyConfig.DefaultSbomNamespaceBaseUri) && !string.IsNullOrEmpty(configuration.NamespaceUriBase?.Value))
        {
            return configuration.NamespaceUriBase;
        }

        // If assembly name is not defined and namespace was not provided then return the default namespace as per spdx spec https://spdx.github.io/spdx-spec/v2.2.2/document-creation-information/#653-examples.
        if (string.IsNullOrWhiteSpace(assemblyConfig.DefaultSbomNamespaceBaseUri) && string.IsNullOrEmpty(configuration.NamespaceUriBase?.Value))
        {
            var defaultNamespaceUriBase = $"https://spdx.org/spdxdocs/sbom-tool-{SbomToolVersion}-{Guid.NewGuid()}";

            logger.Information($"No namespace URI base provided, using unique generated default value {defaultNamespaceUriBase}");

            return new ConfigurationSetting<string>
            {
                Source = SettingSource.Default,
                Value = defaultNamespaceUriBase
            };
        }

        // If the user provides the parameter even when the assembly attribute is provided,
        // show a warning on the console.
        if (!string.IsNullOrWhiteSpace(configuration.NamespaceUriBase?.Value))
        {
            if (!string.IsNullOrWhiteSpace(assemblyConfig.DefaultSbomNamespaceBaseUri))
            {
                logger.Information("Custom namespace URI base provided, using provided value instead of default");
            }

            return configuration.NamespaceUriBase;
        }

        return new ConfigurationSetting<string>
        {
            Source = SettingSource.Default,
            Value = assemblyConfig.DefaultSbomNamespaceBaseUri
        };
    }

    private ConfigurationSetting<string> GetPackageSupplierFromAssembly(IConfiguration configuration, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(assemblyConfig.DefaultPackageSupplier))
        {
            return configuration.PackageSupplier;
        }

        // Give priority to package supplier provided as an argument.
        if (!string.IsNullOrWhiteSpace(configuration.PackageSupplier?.Value))
        {
            if (!string.IsNullOrWhiteSpace(assemblyConfig.DefaultPackageSupplier))
            {
                logger.Information("Custom package supplier value provided, using provided value instead of default");
            }

            return configuration.PackageSupplier;
        }

        return new ConfigurationSetting<string>
        {
            Source = SettingSource.Default,
            Value = assemblyConfig.DefaultPackageSupplier
        };
    }

    /// <summary>
    /// Set ManifestDirPath if the value is null or empty to default value.
    /// </summary>
    private ConfigurationSetting<string> GetManifestDirPath(ConfigurationSetting<string> manifestDirPathConfig, string buildDropPath, ManifestToolActions manifestToolAction)
    {
        if (string.IsNullOrEmpty(manifestDirPathConfig?.Value))
        {
            return new ConfigurationSetting<string>
            {
                Value = fileSystemUtils.JoinPaths(buildDropPath, Constants.ManifestFolder),
                Source = SettingSource.Default
            };
        }

        return new ConfigurationSetting<string>
        {
            Value = EnsurePathEndsWithManifestFolderForGenerate(manifestDirPathConfig.Value, manifestToolAction),
            Source = manifestDirPathConfig.Source
        };
    }

    private string EnsurePathEndsWithManifestFolderForGenerate(string value, ManifestToolActions manifestToolAction)
    {
        if (manifestToolAction == ManifestToolActions.Generate)
        {
            // For generate action, add the _manifest folder at the end of the path
            return fileSystemUtils.JoinPaths(value, Constants.ManifestFolder);
        }

        return value;
    }
}
