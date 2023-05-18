// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using AutoMapper;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Runs finalizing operations on the configuration once it has been successfully parsed.
/// </summary>
public class ConfigPostProcessor : IMappingAction<IConfiguration, IConfiguration>
{
    private readonly IEnumerable<ConfigValidator> configValidators;
    private readonly ConfigSanitizer configSanitizer;
    private readonly IFileSystemUtils fileSystemUtils;

    public ConfigPostProcessor(IEnumerable<ConfigValidator> configValidators, ConfigSanitizer configSanitizer, IFileSystemUtils fileSystemUtils)
    {
        this.configValidators = configValidators ?? throw new ArgumentNullException(nameof(configValidators));
        this.configSanitizer = configSanitizer ?? throw new ArgumentNullException(nameof(configSanitizer));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public void Process(IConfiguration source, IConfiguration destination, ResolutionContext context)
    {
        // Set current action on config validators
        configValidators.ForEach(c => c.CurrentAction = destination.ManifestToolAction);

        foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(destination))
        {
            // Assign default values if any using the default value attribute.
            if (property.GetValue(destination) == null &&
                property.Attributes[typeof(System.ComponentModel.DefaultValueAttribute)]
                    is System.ComponentModel.DefaultValueAttribute defaultValueAttribute)
            {
                SetDefaultValue(destination, defaultValueAttribute.Value, property);
            }

            try
            {
                // Run validators on all properties.
                configValidators.ForEach(v => v.Validate(property.DisplayName, property.GetValue(destination), property.Attributes));
            }
            catch (Exception ex)
            {
                var recorder = TelemetryRecorder.Create(destination, fileSystemUtils);
                _ = recorder.LogException(ex);
                throw;
            }
        }

        // Sanitize configuration
        destination = configSanitizer.SanitizeConfig(destination);
    }

    private void SetDefaultValue(IConfiguration destination, object value, PropertyDescriptor property)
    {
        if (value is string valueString)
        {
            property.SetValue(destination, new ConfigurationSetting<string>
            {
                Value = valueString,
                Source = SettingSource.Default
            });
        }

        if (value is int valueInt)
        {
            property.SetValue(destination, new ConfigurationSetting<int>
            {
                Value = valueInt,
                Source = SettingSource.Default
            });
        }

        if (value is bool valueBool)
        {
            property.SetValue(destination, new ConfigurationSetting<bool>
            {
                Value = valueBool,
                Source = SettingSource.Default
            });
        }

        // Fall through, only primitive types are currently supported. 
        // Add more primitive types if needed here.
    }
}