// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
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
using SbomConstants = Microsoft.Sbom.Common.Constants;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Sanitizes a validated configuration by setting additional parameters or fixing default parameters if needed.
/// </summary>
public class ConfigSanitizer
{
    private readonly IHashAlgorithmProvider hashAlgorithmProvider;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IAssemblyConfig assemblyConfig;

    internal static string SBOMToolVersion => VersionValue.Value;

    private static readonly Lazy<string> VersionValue = new Lazy<string>(() => typeof(SbomToolCmdRunner).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty);

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
            .WriteTo.Console(outputTemplate: SpdxConstants.LoggerTemplate)
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
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            configuration.NamespaceUriBase = GetNamespaceBaseUri(configuration, logger);
        }

        // Set default ManifestInfo for validation in case user doesn't provide a value.
        configuration.ManifestInfo = GetDefaultManifestInfoForValidationAction(configuration);

        // Set default package supplier if not provided in configuration.
        configuration.PackageSupplier = GetPackageSupplierFromAssembly(configuration, logger);

        var configuration2 = configuration as IConfiguration2;
        if (configuration2 is not null)
        {
            // Prevent null value for LicenseInformationTimeoutInSeconds.
            // Values of (0, SpdxConstants.MaxLicenseFetchTimeoutInSeconds] are allowed. Negative values are replaced with the default, and
            // the higher values are truncated to the maximum of Common.SpdxConstants.MaxLicenseFetchTimeoutInSeconds
            if (configuration2.LicenseInformationTimeoutInSeconds is null)
            {
                configuration2.LicenseInformationTimeoutInSeconds = new(SbomConstants.DefaultLicenseFetchTimeoutInSeconds, SettingSource.Default);
            }
            else if (configuration2.LicenseInformationTimeoutInSeconds.Value <= 0)
            {
                logger.Warning($"Negative and Zero Values not allowed for timeout. Using the default {SbomConstants.DefaultLicenseFetchTimeoutInSeconds} seconds instead.");
                configuration2.LicenseInformationTimeoutInSeconds.Value = SbomConstants.DefaultLicenseFetchTimeoutInSeconds;
            }
            else if (configuration2.LicenseInformationTimeoutInSeconds.Value > SbomConstants.MaxLicenseFetchTimeoutInSeconds)
            {
                logger.Warning($"Specified timeout exceeds maximum allowed. Truncating the timeout to {SbomConstants.MaxLicenseFetchTimeoutInSeconds} seconds.");
                configuration2.LicenseInformationTimeoutInSeconds.Value = SbomConstants.MaxLicenseFetchTimeoutInSeconds;
            }

            // Check if arg -lto is specified but -li is not
            if (configuration.FetchLicenseInformation?.Value != true && !configuration2.LicenseInformationTimeoutInSeconds.IsDefaultSource)
            {
                logger.Warning("A license fetching timeout is specified (argument -lto), but this has no effect when FetchLicenseInfo is unspecified or false (argument -li)");
            }
        }

        // Replace backslashes in directory paths with the OS-sepcific directory separator character.
        PathUtils.ConvertToOSSpecificPathSeparators(configuration);

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
            throw new ValidationArgException($"Please provide a value for the SbomPath (-sp) parameter to validate the SBOM.");
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
            throw new ValidationArgException($"Please provide a value for the ManifestInfo (-mi) parameter to validate the SBOM.");
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
                throw new ValidationArgException($"Please provide a (-m) if you intend to create an SBOM with only the contents of the Docker image or a (-bc) if you intend to include other components in your SBOM.");
            }
            else if (configuration.ManifestDirPath?.Value == null && configuration.DockerImagesToScan?.Value != null)
            {
                throw new ValidationArgException($"Please provide a value for the ManifestDirPath (-m) parameter to generate the SBOM for the specified Docker image.");
            }
            else
            {
                throw new ValidationArgException($"Please provide a value for the BuildDropPath (-b) parameter to generate the SBOM.");
            }
        }
        else
        {
            throw new ValidationArgException($"Please provide a value for the BuildDropPath (-b) parameter.");
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

    private ConfigurationSetting<string> GetNamespaceBaseUri(IConfiguration configuration, ILogger logger)
    {
        // If assembly name is not defined but a namespace was provided, then return the current value.
        if (string.IsNullOrWhiteSpace(assemblyConfig.DefaultSBOMNamespaceBaseUri) && !string.IsNullOrEmpty(configuration.NamespaceUriBase?.Value))
        {
            return configuration.NamespaceUriBase;
        }

        // If assembly name is not defined and namespace was not provided then return the default namespace as per spdx spec https://spdx.github.io/spdx-spec/v2.2.2/document-creation-information/#653-examples.
        if (string.IsNullOrWhiteSpace(assemblyConfig.DefaultSBOMNamespaceBaseUri) && string.IsNullOrEmpty(configuration.NamespaceUriBase?.Value))
        {
            var defaultNamespaceUriBase = $"https://spdx.org/spdxdocs/sbom-tool-{SBOMToolVersion}-{Guid.NewGuid()}";

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
            if (!string.IsNullOrWhiteSpace(assemblyConfig.DefaultSBOMNamespaceBaseUri))
            {
                logger.Information("Custom namespace URI base provided, using provided value instead of default");
            }

            return configuration.NamespaceUriBase;
        }

        return new ConfigurationSetting<string>
        {
            Source = SettingSource.Default,
            Value = assemblyConfig.DefaultSBOMNamespaceBaseUri
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
                Value = fileSystemUtils.JoinPaths(buildDropPath, SpdxConstants.ManifestFolder),
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
            return fileSystemUtils.JoinPaths(value, SpdxConstants.ManifestFolder);
        }

        return value;
    }
}
