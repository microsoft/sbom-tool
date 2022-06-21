using System.Diagnostics.Tracing;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Define additional configuration keys here to tweak the execution of the SBOM library.
    /// </summary>
    public class RuntimeConfiguration
    {
        /// <summary>
        /// Define the number of parallel workflow threads to run. Tweak this value
        /// based on your build machine configuration.
        /// </summary>
        public int WorkflowParallelism { get; set; }

        /// <summary>
        /// If set, we will delete any _manifest directory in the root path before creating a 
        /// new SBOM. If there is already a _manifest directory in the root path and this switch
        /// is false, we will fail SBOM generation.
        /// </summary>
        public bool DeleteManifestDirectoryIfPresent { get; set; }

        /// <summary>
        /// Set the level of logging.
        /// </summary>
        public EventLevel Verbosity { get; set; }

        /// <summary>
        /// Unique part of the namespace uri for SPDX 2.2 SBOMs. This value should be globally unique.
        /// If this value is not provided, we generate a unique guid that will make the namespace globally unique.
        /// </summary>
        public string NamespaceUriUniquePart { get; set; }

        /// <summary>
        /// The base of the URI that will be used to generate this SBOM. This should be a value that identifies that
        /// the SBOM belongs to a single publisher (or company)
        /// </summary>
        public string NamespaceUriBase { get; set; }

        /// <summary>
        /// A timestamp in the format <code>yyyy-MM-ddTHH:mm:ssZ</code> that will be used as the generated timestamp for the SBOM.
        /// </summary>
        public string GenerationTimestamp { get; set; }

        /// <summary>
        /// If set to false, we will not follow symlinks while traversing the build drop folder.
        /// </summary>
        public bool FollowSymlinks { get; set; } = true;
    }
}
