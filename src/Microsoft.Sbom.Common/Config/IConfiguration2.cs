// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Config;

/// <summary>
/// This holds the configuration for the ManifestTool. The values in this
/// file are populated from the command line or config file. Some values
/// are set by default.
/// </summary>
public interface IConfiguration2 : IConfiguration
{
    /// <summary>
    /// Specifies the timeout in seconds for fetching the license information. Defaults to <see cref="Constants.DefaultLicenseFetchTimeoutInSeconds"/>.
    /// Has no effect if FetchLicenseInformation (li) argument is false or not provided. Negative values are set to the default and values exceeding the
    /// maximum are truncated to <see cref="Constants.MaxLicenseFetchTimeoutInSeconds"/>
    /// </summary>
    ConfigurationSetting<int> LicenseInformationTimeoutInSeconds { get; set; }
}
