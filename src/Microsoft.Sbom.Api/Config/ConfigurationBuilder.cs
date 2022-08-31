// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using PowerArgs;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Config.Args;

namespace Microsoft.Sbom.Api.Config
{
    /// <summary>
    /// Converts the command line arguments and config file parameters to <see cref="ConfigurationSetting{T}"/> objects.
    /// Finally combines the two into one <see cref="IConfiguration"/> object.
    /// 
    /// Throws an error if the same parameters are defined in both the config file and command line.
    /// </summary>
    /// <typeparam name="T">The action args parameter.</typeparam>
    public class ConfigurationBuilder<T>
    {
        private readonly IMapper mapper;
        private readonly ConfigFileParser configFileParser;

        public ConfigurationBuilder(IMapper mapper, ConfigFileParser configFileParser)
        {
            this.mapper = mapper;
            this.configFileParser = configFileParser;
        }

        public async Task<IConfiguration> GetConfiguration(T args)
        {
            Configuration commandLineArgs;

            // Set current action for the config validators and convert command line arguments to configuration
            switch (args)
            {
                case ValidationArgs validationArgs:
                    validationArgs.ManifestToolAction = ManifestToolActions.Validate;
                    commandLineArgs = mapper.Map<Configuration>(validationArgs);
                    break;
                case GenerationArgs generationArgs:
                    generationArgs.ManifestToolAction = ManifestToolActions.Generate;
                    commandLineArgs = mapper.Map<Configuration>(generationArgs);
                    break;
                default:
                    throw new ValidationArgException($"Unsupported configuration type found {typeof(T)}");
            }

            // Read config file if present, or use default.
            var configFromFile = commandLineArgs.ConfigFilePath != null ?
                                        await configFileParser.ParseFromJsonFile(commandLineArgs.ConfigFilePath.Value) :
                                        new ConfigFile();

            // Convert config file arguments to configuration.
            var configFileArgs = mapper.Map<ConfigFile, Configuration>(configFromFile);

            // Combine both configs, include defaults.
            return mapper.Map(commandLineArgs, configFileArgs);
        }
    }
}
