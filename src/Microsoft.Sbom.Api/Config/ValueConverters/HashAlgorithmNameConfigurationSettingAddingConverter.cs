// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts an LogEventLevel member to a ConfigurationSetting decorated string member.
/// </summary>
internal class HashAlgorithmNameConfigurationSettingAddingConverter : IValueConverter<AlgorithmName, ConfigurationSetting<AlgorithmName>>
{
    private SettingSource settingSource;

    public HashAlgorithmNameConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<AlgorithmName> Convert(AlgorithmName sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            settingSource = SettingSource.Default;
        }

        return new ConfigurationSetting<AlgorithmName>
        {
            Source = settingSource,
            Value = sourceMember ?? Constants.DefaultHashAlgorithmName
        };
    }
}
