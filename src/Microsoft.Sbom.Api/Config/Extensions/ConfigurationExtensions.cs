// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using AutoMapper.Configuration;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using PowerArgs;
using System;
using System.Collections.Generic;
using System.Linq;
using IConfiguration = Microsoft.Sbom.Common.Config.IConfiguration;

namespace Microsoft.Sbom.Api.Config.Extensions
{
    /// <summary>
    /// Provides extension methods for an instance of <see cref="IConfiguration"/>.
    /// </summary>
    public static class ConfigurationExtensions
    {
        /// <summary>
        /// Get the name and value of each IConfiguration property that is annotated with <see cref=ComponentDetectorArgumentAttribute />.
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        private static IEnumerable<(string Name, object Value)> GetComponentDetectorArgs(this IConfiguration configuration) => typeof(IConfiguration)
            .GetProperties()
            .Where(prop => prop.GetCustomAttributes(typeof(ComponentDetectorArgumentAttribute), true).Any()
                && prop.PropertyType.GetGenericTypeDefinition() == typeof(ConfigurationSetting<>)
                && prop.GetValue(configuration) != null)
            .Select(prop => (prop.Attr<ComponentDetectorArgumentAttribute>().ParameterName, prop.GetValue(configuration)));

        /// <summary>
        /// Adds component detection arguments to the builder.
        /// </summary>
        /// <param name="arg"></param>
        /// <param name="builder"></param>
        /// <returns></returns>
        private static ComponentDetectionCliArgumentBuilder AddToCommandLineBuilder(this (string Name, object Value) arg, ComponentDetectionCliArgumentBuilder builder) =>
            !string.IsNullOrWhiteSpace(arg.Name) ? builder.AddArg(arg.Name, arg.Value.ToString()) : builder.ParseAndAddArgs(arg.Value.ToString());

        /// <summary>
        /// Adds command line arguments for all <see cref="IConfiguration"/> properties annotated with <see cref="ComponentDetectorArgumentAttribute"/> to the current CD CLI arguments builder and returns array of arguments.
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static string[] ToComponentDetectorCommandLineParams(this IConfiguration configuration, ComponentDetectionCliArgumentBuilder builder)
        {
            configuration
                .GetComponentDetectorArgs()
                .ForEach(arg => arg.AddToCommandLineBuilder(builder));
            return builder.Build();
        }

        // Map the validated InputConfiguration to a Configuration, which will persist the mapping statically and globally
        public static Configuration ToConfiguration(this InputConfiguration inputConfig, IEnumerable<ConfigValidator> configValidators, ConfigSanitizer configSanitizer) =>
            new MapperConfiguration(cfg => cfg.CreateMap<InputConfiguration, Configuration>()
            .AfterMap((_, configuration) => new ConfigPostProcessor(configValidators, configSanitizer).Process(configuration))
                    .ForAllMembers(dest => dest.Condition((src, dest, srcObj, dstObj) =>
                    {
                        // If the property is set in both source and destination (config and cmdline,
                        // this is a failure case, unless one of the property is a default value, in which
                        // case the non default value wins.
                        if (srcObj != null && dstObj != null
                            && srcObj is ISettingSourceable srcWithSource
                            && dstObj is ISettingSourceable dstWithSource)
                        {
                            if (srcWithSource.Source != SettingSource.Default && dstWithSource.Source != SettingSource.Default)
                            {
                                throw new Exception($"Duplicate keys found in config file and command line parameters.");
                            }

                            return dstWithSource.Source == SettingSource.Default;
                        }

                        // If source property is not null, use source, or else use destination value.
                        return srcObj != null;
                    })))
            .CreateMapper()
            .Map<Configuration>(inputConfig);
    }
}