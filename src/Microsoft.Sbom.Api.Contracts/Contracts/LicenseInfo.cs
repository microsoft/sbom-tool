namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Defines license strings for an entity.
    /// </summary>
    public class LicenseInfo
    {
        /// <summary>
        /// Gets or sets the declared license of this entity. This was explicitly declared
        /// by the owner of this entity.
        /// </summary>
        public string Declared { get; set; }

        /// <summary>
        /// Gets or sets the concluded license of this entity. This was inferred based on the
        /// context in which this entity exists.
        /// </summary>
        public string Concluded { get; set; }
    }
}
