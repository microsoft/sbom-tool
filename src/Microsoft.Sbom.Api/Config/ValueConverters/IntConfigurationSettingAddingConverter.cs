// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts the int property to a ConfigurationSetting decorated member
/// Int.MinValue is considered invalid.
/// </summary>
internal class IntConfigurationSettingAddingConverter : IValueConverter<int?, ConfigurationSetting<int>>, IValueConverter<int, ConfigurationSetting<int>>
{
    private readonly SettingSource settingSource;

    public IntConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<int> Convert(int? sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            return null;
        }

        return Convert(sourceMember.Value, context);
    }

    public ConfigurationSetting<int> Convert(int sourceMember, ResolutionContext context)
    {
        return new ConfigurationSetting<int>
        {
            Source = settingSource,
            Value = sourceMember
        };
    }
}
