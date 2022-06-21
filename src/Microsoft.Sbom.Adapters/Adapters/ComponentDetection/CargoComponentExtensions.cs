using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="CargoComponent"/>.
    /// </summary>
    internal static class CargoComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="CargoComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this CargoComponent cargoComponent) => new SBOMPackage
        {
            Id = cargoComponent.Id,
            PackageUrl = cargoComponent.PackageUrl?.ToString(),
            PackageName = cargoComponent.Name,
            PackageVersion = cargoComponent.Version,
            FilesAnalyzed = false,
            Type = "cargo"
        };
    }
}
