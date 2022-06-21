using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="CondaComponent"/>.
    /// </summary>
    internal static class CondaComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="CondaComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this CondaComponent condaComponent) => new SBOMPackage
        {
            Id = condaComponent.Id,
            PackageUrl = condaComponent.PackageUrl?.ToString(),
            PackageName = condaComponent.Name,
            PackageVersion = condaComponent.Version,
            PackageSource = condaComponent.Url,
            Checksum = new List<Checksum>()
                {
                    new Checksum()
                    {
                        Algorithm = AlgorithmName.MD5,
                        ChecksumValue = condaComponent.MD5
                    },
                },
            FilesAnalyzed = false,
            Type = "conda"
        };
    }
}
