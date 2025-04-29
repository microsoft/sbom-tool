// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts a Conformance member to a ConfigurationSetting decorated string member.
/// </summary>
internal class ConformanceStandardConfigurationSettingAddingConverter : IValueConverter<ConformanceStandardType?, ConfigurationSetting<ConformanceStandardType>>
{
    private SettingSource settingSource;

    public ConformanceStandardConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<ConformanceStandardType> Convert(ConformanceStandardType? sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            settingSource = SettingSource.Default;
        }

        return new ConfigurationSetting<ConformanceStandardType>
        {
            Source = settingSource,
            Value = sourceMember ?? ConformanceStandardType.None
        };
    }
}
