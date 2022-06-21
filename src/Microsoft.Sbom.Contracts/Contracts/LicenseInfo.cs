namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Defines license strings for an entity.
    /// </summary>
    public class LicenseInfo
    {
        /// <summary>
        /// The declared license of this entity. This was explicitly declared
        /// by the owner of this entity.
        /// </summary>
        public string Declared { get; set; }

        /// <summary>
        /// The concluded license of this entity. This was inferred based on the
        /// context in which this entity exists.
        /// </summary>
        public string Concluded { get; set; }
    }
}
