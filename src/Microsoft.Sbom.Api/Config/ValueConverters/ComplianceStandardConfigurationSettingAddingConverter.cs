// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts a ComplianceStandard member to a ConfigurationSetting decorated string member.
/// </summary>
internal class ComplianceStandardConfigurationSettingAddingConverter : IValueConverter<ComplianceStandardType?, ConfigurationSetting<ComplianceStandardType>>
{
    private SettingSource settingSource;

    public ComplianceStandardConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<ComplianceStandardType> Convert(ComplianceStandardType? sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            settingSource = SettingSource.Default;
        }

        return new ConfigurationSetting<ComplianceStandardType>
        {
            Source = settingSource,
            Value = sourceMember ?? ComplianceStandardType.None
        };
    }
}
