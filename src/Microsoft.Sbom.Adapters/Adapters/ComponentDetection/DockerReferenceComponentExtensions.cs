using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="DockerReferenceComponent"/>.
    /// </summary>
    internal static class DockerReferenceComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="DockerReferenceComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this DockerReferenceComponent dockerReferenceComponent) => new SBOMPackage
        {
            Id = dockerReferenceComponent.Id,
            PackageUrl = dockerReferenceComponent.PackageUrl?.ToString(),
            PackageName = dockerReferenceComponent.Name,
            Checksum = new List<Checksum>()
                {
                    new Checksum()
                    {
                        Algorithm = AlgorithmName.SHA256,
                        ChecksumValue = dockerReferenceComponent.Digest
                    },
                },
            FilesAnalyzed = false,
            Type = "docker-reference"
        };
    }
}
