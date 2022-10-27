using Microsoft.ComponentDetection.Detectors.Linux.Contracts;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Entities;
using System;

namespace Microsoft.Sbom.Api.Manifest.FileHashes
{
    public class FileHashes
    {
        public Checksum OnDiskHash { get; private set; }
        
        public Checksum SBOMFileHash { get; private set; }

        public bool OnDiskHashPresent { get; set; } = false;
        
        public bool SbomFileHashPresent { get; set; } = false;

        public FileLocation FileLocation { get; private set; } = FileLocation.None;

        public Checksum GetHash(FileLocation fileLocation) => fileLocation switch
        {
            FileLocation.OnDisk => OnDiskHash,
            FileLocation.InSbomFile => SBOMFileHash,
            _ => throw new Exception("Unknown file location type for SBOM file."),
        };


        public void SetHash(FileLocation fileLocation, Checksum checksum)
        {
            switch (fileLocation)
            {
                case FileLocation.OnDisk: 
                    OnDiskHash = checksum;
                    break;
                case FileLocation.InSbomFile: 
                    SBOMFileHash = checksum; 
                    break;
                default:
                    break;
            }
            FileLocation |= fileLocation;
        }
    }
}
