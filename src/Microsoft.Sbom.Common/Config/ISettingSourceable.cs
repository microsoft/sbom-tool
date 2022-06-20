namespace Microsoft.Sbom.Common.Config
{
    /// <summary>
    /// Adds a setting source property to an object that defines where that setting came from.
    /// </summary>
    public interface ISettingSourceable
    {
        /// <summary>
        /// The <see cref="SettingSource">source</see> where this setting came from.
        /// </summary>
        SettingSource Source { get; set; }
    }
}
