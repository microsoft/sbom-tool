using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="GoComponent"/>.
    /// </summary>
    internal static class GoComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="GoComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this GoComponent goComponent) => new SBOMPackage
        {
            Id = goComponent.Id,
            PackageUrl = goComponent.PackageUrl?.ToString(),
            PackageName = goComponent.Name,
            PackageVersion = goComponent.Version,
            Checksum = new List<Checksum>()
                {
                    new Checksum()
                    {
                        Algorithm = AlgorithmName.SHA256,
                        ChecksumValue = goComponent.Hash
                    },
                },
            FilesAnalyzed = false,
            Type = "go"

        };
    }
}
