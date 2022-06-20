using ManifestInterface;
using ManifestInterface.Entities;

namespace Microsoft.Sbom.Common
{
    /// <summary>
    /// Factory that instantiate ISbomConfig based on parameters.
    /// </summary>
    public interface ISbomConfigFactory
    {
        /// <summary>
        /// Gets new instance of ISbomConfig.
        /// </summary>
        public ISbomConfig Get(
            ManifestInfo manifestInfo,
            string manifestDirPath,
            string manifestFilePath,
            ISbomPackageDetailsRecorder recorder,
            IMetadataBuilder metadataBuilder
        );
    }
}
