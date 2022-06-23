// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Attributes;
using PowerArgs;
using System.Collections.Generic;
using System.Linq;

namespace DropValidator.Api.Config.Extensions
{
    /// <summary>
    /// Provides extension methods for an instance of <see cref="IConfiguration"/>.
    /// </summary>
    public static class ConfigurationExtensions
    {
        /// <summary>
        /// Get the name and value of each IConfiguration property that is annotated with <see cref=ComponentDetectorArgumentAttribute />..
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
    }
}