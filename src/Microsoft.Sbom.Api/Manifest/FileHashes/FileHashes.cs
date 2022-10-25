using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Manifest.FileHashes
{
    public class FileHashes
    {
        public Checksum OnDiskHash { get; set; }
        
        public Checksum SBOMFileHash { get; set; }

        public bool OnDiskHashPresent { get; set; } = false;
        
        public bool SbomFileHashPresent { get; set; } = false;  
    }
}
