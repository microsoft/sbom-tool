using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="PipComponent"/>.
    /// </summary>
    internal static class SbomPackageExtensions
    {
        /// <summary>
        /// Converts a <see cref="PipComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this PipComponent pipComponent) => new SBOMPackage
        {
            Id = pipComponent.Id,
            PackageUrl = pipComponent.PackageUrl?.ToString(),
            PackageName = pipComponent.Name,
            PackageVersion = pipComponent.Version,
            FilesAnalyzed = false,
            Type = "python"
        };
    }
}
