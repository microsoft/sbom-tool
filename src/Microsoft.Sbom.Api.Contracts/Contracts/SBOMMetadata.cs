using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Use this class to provide addtional metadata to the SBOM generator 
    /// about your specific environment.
    /// </summary>
    public class SBOMMetadata
    {
        /// <summary>
        /// The name of your build environment, like CloudBuild or Azure Pipelines.
        /// </summary>
        public string BuildEnvironmentName { get; set; }

        /// <summary>
        /// The unique name of the build that can be used to identify the
        /// build in your build system.
        /// </summary>
        public string BuildName { get; set; }

        /// <summary>
        /// The run id of the build.
        /// </summary>
        public string BuildId { get; set; }

        /// <summary>
        /// The uri to identify the repository where the source for this build is located at.
        /// </summary>
        public string RepositoryUri { get; set; }

        /// <summary>
        /// The specific commmit id that was used to generate this build.
        /// </summary>
        public string CommitId { get; set; }

        /// <summary>
        /// The name of the branch of the repository used to generate this build.
        /// </summary>
        public string Branch { get; set; }

        /// <summary>
        /// The name of the package this SBOM represents. If this is not provided we will 
        /// try to generate a unique package name based on the build name and id.
        /// </summary>
        public string PackageName { get; set; }

        /// <summary>
        /// The version of the package this SBOM represents. If this is not provided we will 
        /// try to generate a unique package name based on the build name and id.
        /// </summary>
        public string PackageVersion { get; set; }
    }
}
