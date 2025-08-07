// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using AutoMapper;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

internal class ArtifactInfoMapSettingAddingConverter : IValueConverter<Dictionary<string, ArtifactInfo>, ConfigurationSetting<Dictionary<string, ArtifactInfo>>>
{
    private readonly SettingSource settingSource;

    public ArtifactInfoMapSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<Dictionary<string, ArtifactInfo>> Convert(Dictionary<string, ArtifactInfo> sourceMember, ResolutionContext context)
    {
        if (sourceMember == null || !sourceMember.Any())
        {
            return null;
        }

        return new ConfigurationSetting<Dictionary<string, ArtifactInfo>>
        {
            Source = settingSource,
            Value = sourceMember
        };
    }
}
