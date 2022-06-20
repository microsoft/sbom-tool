namespace Microsoft.Sbom.Common.Config
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
        /// THe setting was set using the config json file.
        /// </summary>
        JsonConfig,

        /// <summary>
        /// The settings was set using the SBOM Api.
        /// </summary>
        SBOMApi
    }
}
