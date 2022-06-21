using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="PodComponent"/>.
    /// </summary>
    internal static class PodComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="PodComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this PodComponent podComponent) => new SBOMPackage
        {
            Id = podComponent.Id,
            PackageUrl = podComponent.PackageUrl?.ToString(),
            PackageName = podComponent.Name,
            PackageVersion = podComponent.Version,
            PackageSource = podComponent.SpecRepo,
            FilesAnalyzed = false,
            Type = "pod"
        };
    }
}
