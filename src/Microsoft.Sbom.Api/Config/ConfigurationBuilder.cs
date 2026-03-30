// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Common.Config;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config;

/// <inheritdoc />
/// <remarks>Throws an error if the same parameters are defined in both the config file and command line.</remarks>
public class ConfigurationBuilder<T> : IConfigurationBuilder<T>
{
    private readonly ConfigPostProcessor configPostProcessor;
    private readonly ConfigFileParser configFileParser;

    public ConfigurationBuilder(ConfigPostProcessor configPostProcessor, ConfigFileParser configFileParser)
    {
        this.configPostProcessor = configPostProcessor;
        this.configFileParser = configFileParser;
    }

    public async Task<InputConfiguration> GetConfiguration(T args)
    {
        InputConfiguration commandLineArgs;

        // Set current action for the config validators and convert command line arguments to configuration
        switch (args)
        {
            case ValidationArgs validationArgs:
                validationArgs.ManifestToolAction = ManifestToolActions.Validate;
                commandLineArgs = ConfigurationMapper.MapFrom(validationArgs);
                break;
            case GenerationArgs generationArgs:
                generationArgs.ManifestToolAction = ManifestToolActions.Generate;
                commandLineArgs = ConfigurationMapper.MapFrom(generationArgs);
                break;
            case RedactArgs redactArgs:
                redactArgs.ManifestToolAction = ManifestToolActions.Redact;
                commandLineArgs = ConfigurationMapper.MapFrom(redactArgs);
                break;
            case FormatValidationArgs formatValidationArgs:
                formatValidationArgs.ManifestToolAction = ManifestToolActions.ValidateFormat;
                commandLineArgs = ConfigurationMapper.MapFrom(formatValidationArgs);
                break;
            case AggregationArgs aggregationArgs:
                aggregationArgs.ManifestToolAction = ManifestToolActions.Aggregate;
                commandLineArgs = ConfigurationMapper.MapFrom(aggregationArgs);
                break;
            default:
                throw new ValidationArgException($"Unsupported configuration type found {typeof(T)}");
        }

        // Read config file if present, or use default.
        var configFromFile = commandLineArgs.ConfigFilePath != null ?
            await configFileParser.ParseFromJsonFile(commandLineArgs.ConfigFilePath.Value) :
            new ConfigFile();

        // Convert config file arguments to configuration.
        var configFileArgs = ConfigurationMapper.MapFrom(configFromFile);

        // Combine both configs, include defaults.
        return ConfigurationMapper.Merge(commandLineArgs, configFileArgs, configPostProcessor);
    }
}

/// <summary>
/// Converts the command line arguments and config file parameters to <see cref="ConfigurationSetting{T}"/> objects.
/// Finally combines the two into one <see cref="IConfiguration"/> object.
/// </summary>
/// <typeparam name="T">The action args parameter.</typeparam>
public interface IConfigurationBuilder<T>
{
    public Task<InputConfiguration> GetConfiguration(T args);
}
