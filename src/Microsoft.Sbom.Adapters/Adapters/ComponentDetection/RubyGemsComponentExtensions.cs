using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="RubyGemsComponent"/>.
    /// </summary>
    internal static class RubyGemsComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="RubyGemsComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this RubyGemsComponent rubyGemsComponent) => new SBOMPackage
        {
            Id = rubyGemsComponent.Id,
            PackageUrl = rubyGemsComponent.PackageUrl?.ToString(),
            PackageName = rubyGemsComponent.Name,
            PackageVersion = rubyGemsComponent.Version,
            PackageSource = rubyGemsComponent.Source,
            FilesAnalyzed = false,
            Type = "ruby"
        };
    }
}
