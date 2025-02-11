// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Common.Config;
using Serilog.Events;
using SbomConstants = Microsoft.Sbom.Common.Constants;

namespace Microsoft.Sbom.Api.Config.ValueConverters;

/// <summary>
/// Converts an LogEventLevel member to a ConfigurationSetting decorated string member.
/// </summary>
internal class LogEventLevelConfigurationSettingAddingConverter : IValueConverter<LogEventLevel?, ConfigurationSetting<LogEventLevel>>
{
    private SettingSource settingSource;

    public LogEventLevelConfigurationSettingAddingConverter(SettingSource settingSource)
    {
        this.settingSource = settingSource;
    }

    public ConfigurationSetting<LogEventLevel> Convert(LogEventLevel? sourceMember, ResolutionContext context)
    {
        if (sourceMember == null)
        {
            settingSource = SettingSource.Default;
        }

        return new ConfigurationSetting<LogEventLevel>
        {
            Source = settingSource,
            Value = sourceMember ?? SbomConstants.DefaultLogLevel
        };
    }
}
