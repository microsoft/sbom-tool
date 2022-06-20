using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Entities;

namespace Microsoft.Sbom
{
    public interface ISbomPackageDetailsRecorder
    {
        /// <summary>
        /// Record a fileId that is included in this SBOM.
        /// </summary>
        /// <param name="fileId"></param>
        void RecordFileId(string fileId);

        /// <summary>
        /// Record a fileId for SPDX files that are referenced in the SBOM.
        /// </summary>
        void RecordSPDXFileId(string spdxFileId);

        /// <summary>
        /// Record a packageId that is included in this SBOM.
        /// </summary>
        /// <param name="packageId"></param>
        void RecordPackageId(string packageId);

        /// <summary>
        /// Record a externalDocumentReference Id that is included in this SBOM.
        /// </summary>
        /// <param name="fileId"></param>
        void RecordExternalDocumentReferenceIdAndRootElement(string externalDocumentReferenceId, string rootElement);

        /// <summary>
        /// Gets SBOM generation data.
        /// </summary>
        GenerationData GetGenerationData();

        /// <summary>
        /// Record the SHA1 hash for the file.
        /// </summary>
        /// <param name="hash"></param>
        void RecordChecksumForFile(Checksum[] checksums);

        /// <summary>
        /// Record ID of the root package.
        /// </summary>
        void RecordRootPackageId(string rootPackageId);

        /// <summary>
        /// Record Document ID.
        /// </summary>
        void RecordDocumentId(string documentId);
    }
}
