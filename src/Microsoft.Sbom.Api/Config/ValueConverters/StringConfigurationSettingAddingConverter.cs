// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts a string member to a ConfigurationSetting decorated string member.
/// </summary>
internal class StringConfigurationSettingAddingConverter : IValueConverter<string, ConfigurationSetting<string>>
{
    private readonly SettingSource settingSource;

    public StringConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<string> Convert(string sourceMember, ResolutionContext context)
    {
        if (string.IsNullOrEmpty(sourceMember))
        {
            return null;
        }

        return new ConfigurationSetting<string>
        {
            Source = settingSource,
            Value = sourceMember
        };
    }
}
