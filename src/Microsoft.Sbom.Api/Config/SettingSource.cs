// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Config
{
    /// <summary>
    /// Defines the source of the configuration setting.
    /// </summary>
    public enum SettingSource
    {
        /// <summary>
        /// The setting was set by the validator.
        /// </summary>
        Default = 0,

        /// <summary>
        /// The setting was set using a command line arg.
        /// </summary>
        CommandLine,

        /// <summary>
        /// The setting was set using the config json file.
        /// </summary>
        JsonConfig,

        /// <summary>
        /// The settings was set using the SBOM Api.
        /// </summary>
        SBOMApi
    }
}
