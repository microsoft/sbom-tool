// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Common.Config;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config;

/// <inheritdoc />
/// <remarks>Throws an error if the same parameters are defined in both the config file and command line.</remarks>
public class ConfigurationBuilder<T> : IConfigurationBuilder<T>
{
    private readonly IMapper mapper;
    private readonly ConfigFileParser configFileParser;

    public ConfigurationBuilder(IMapper mapper, ConfigFileParser configFileParser)
    {
        this.mapper = mapper;
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
                commandLineArgs = mapper.Map<InputConfiguration>(validationArgs);
                break;
            case GenerationArgs generationArgs:
                generationArgs.ManifestToolAction = ManifestToolActions.Generate;
                commandLineArgs = mapper.Map<InputConfiguration>(generationArgs);
                break;
            case RedactArgs redactArgs:
                redactArgs.ManifestToolAction = ManifestToolActions.Redact;
                commandLineArgs = mapper.Map<InputConfiguration>(redactArgs);
                break;
            default:
                throw new ValidationArgException($"Unsupported configuration type found {typeof(T)}");
        }

        // Read config file if present, or use default.
        var configFromFile = commandLineArgs.ConfigFilePath != null ?
            await configFileParser.ParseFromJsonFile(commandLineArgs.ConfigFilePath.Value) :
            new ConfigFile();

        // Convert config file arguments to configuration.
        var configFileArgs = mapper.Map<ConfigFile, InputConfiguration>(configFromFile);

        // Combine both configs, include defaults.
        return mapper.Map(commandLineArgs, configFileArgs);
    }
}

/// <summary>
/// Converts the command line arguments and config file parameters to <see cref="ConfigurationSetting{T}"/> objects.
/// Finally combines the two into one <see cref="IConfiguration"/> object.
/// </summary>
/// <typeparam name="T">The action args parameter.</typeparam>
public interface IConfigurationBuilder<T>
{
    Task<InputConfiguration> GetConfiguration(T args);
}
