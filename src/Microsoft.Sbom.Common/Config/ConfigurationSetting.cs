// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Config;

/// <summary>
/// Encapsulates a configuration setting to provide metadata about
/// the setting source and type.
/// </summary>
/// <typeparam name="T"></typeparam>
public class ConfigurationSetting<T> : ISettingSourceable
{
    /// <summary>
    /// Constructs a new instance of <see cref="ConfigurationSetting"/>.
    /// </summary>
    public ConfigurationSetting() { }

    /// <summary>
    /// Constructs a new instance of <see cref="ConfigurationSetting"/> with the provided value.
    /// </summary>
    public ConfigurationSetting(T value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets or sets the actual value of the setting.
    /// </summary>
    public T Value { get; set; }

    /// <summary>
    /// Gets or sets the <see cref="SettingSource">source</see> where this setting came from.
    /// </summary>
    public SettingSource Source { get; set; }

    /// <summary>
    /// Constructs a new instance of <see cref="ConfigurationSetting"/> with the provided value and <see cref="SettingSource"/>.
    /// </summary>
    public ConfigurationSetting(T value, SettingSource source)
    {
        Value = value;
        Source = source;
    }

    /// <summary>
    /// Returns the string representation of <see cref="Value"/>.
    /// </summary>
    /// <returns></returns>
    public override string ToString() => Value?.ToString() ?? base.ToString();

    /// <summary>
    /// Gets a value indicating whether returns whether the <see cref="SettingSource"/> for the this ConfigurationSetting is the default source (i.e. not user-supplied).
    /// </summary>
    public bool IsDefaultSource => Source == SettingSource.Default;
}
