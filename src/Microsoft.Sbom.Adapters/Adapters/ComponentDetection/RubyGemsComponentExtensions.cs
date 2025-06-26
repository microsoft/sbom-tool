// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Linq;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="RubyGemsComponent" />.
/// </summary>
internal static class RubyGemsComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="RubyGemsComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="rubyGemsComponent">The <see cref="RubyGemsComponent" /> to convert.</param>
    /// <param name="component">The <see cref="ExtendedScannedComponent"/> version of the RubyGemsComponent</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage ToSbomPackage(this RubyGemsComponent rubyGemsComponent, ExtendedScannedComponent component) => new()
    {
        Id = rubyGemsComponent.Id,
        PackageUrl = rubyGemsComponent.PackageUrl?.ToString(),
        PackageName = rubyGemsComponent.Name,
        PackageVersion = rubyGemsComponent.Version,
        PackageSource = rubyGemsComponent.Source,
        Supplier = string.IsNullOrEmpty(component.Supplier) ? null : $"Person: {component.Supplier}",
        LicenseInfo = new LicenseInfo
        {
            Concluded = string.IsNullOrEmpty(component.LicenseConcluded) ? null : component.LicenseConcluded,
            Declared = string.IsNullOrEmpty(component.LicenseDeclared) ? null : component.LicenseDeclared,
        },
        FilesAnalyzed = false,
        Type = "ruby",
        DependOn = component.AncestralReferrers?.Select(r => r.Id).ToList(),
    };
}
