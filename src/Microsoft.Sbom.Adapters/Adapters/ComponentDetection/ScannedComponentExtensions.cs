// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.ComponentDetection.Logging;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="ExtendedScannedComponent"/>.
/// </summary>
public static class ScannedComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="ExtendedScannedComponent"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this ExtendedScannedComponent component, AdapterReport report)
    {
        return component.Component switch
        {
            CargoComponent cargoComponent => cargoComponent.ToSbomPackage(component?.LicenseConcluded),
            CondaComponent condaComponent => condaComponent.ToSbomPackage(),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToSbomPackage(),
            GitComponent gitComponent => gitComponent.ToSbomPackage(),
            GoComponent goComponent => goComponent.ToSbomPackage(),
            LinuxComponent linuxComponent => linuxComponent.ToSbomPackage(),
            MavenComponent mavenComponent => mavenComponent.ToSbomPackage(component?.LicenseDeclared, component?.Supplier),
            NpmComponent npmComponent => npmComponent.ToSbomPackage(component?.LicenseConcluded),
            NuGetComponent nuGetComponent => nuGetComponent.ToSbomPackage(component?.LicenseConcluded, component?.LicenseDeclared, component?.Supplier),
            OtherComponent otherComponent => otherComponent.ToSbomPackage(),
            PipComponent pipComponent => pipComponent.ToSbomPackage(component?.LicenseConcluded),
            PodComponent podComponent => podComponent.ToSbomPackage(component?.LicenseConcluded),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToSbomPackage(component?.LicenseConcluded),
            null => Error(report => report.LogNullComponent(nameof(ToSbomPackage))),
            _ => Error(report => report.LogNoConversionFound(component.Component.GetType(), component.Component))
        };

        // Logs an error prior to returning null.
        SbomPackage? Error(Action<AdapterReport> log)
        {
            log(report);
            return null;
        }
    }
}
