// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts a nullable bool member to a ConfigurationSetting decorated string member.
/// </summary>
internal class NullableBoolConfigurationSettingAddingConverter : IValueConverter<bool?, ConfigurationSetting<bool>>
{
    private readonly SettingSource settingSource;

    public NullableBoolConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<bool> Convert(bool? sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            return null;
        }

        return new ConfigurationSetting<bool>
        {
            Source = settingSource,
            Value = sourceMember.Value
        };
    }
}
