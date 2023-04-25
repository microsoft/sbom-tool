// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using AutoMapper;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts an ManifestInfo member to a ConfigurationSetting decorated string member.
/// </summary>
internal class ManifestInfoConfigurationSettingAddingConverter : IValueConverter<IList<ManifestInfo>, ConfigurationSetting<IList<ManifestInfo>>>
{
    private SettingSource settingSource;

    public ManifestInfoConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<IList<ManifestInfo>> Convert(IList<ManifestInfo> sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            settingSource = SettingSource.Default;
            sourceMember = null;
        }

        return new ConfigurationSetting<IList<ManifestInfo>>
        {
            Source = settingSource,
            Value = sourceMember
        };
    }
}