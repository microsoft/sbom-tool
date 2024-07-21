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
            CargoComponent cargoComponent => cargoComponent.ToSbomPackage(component),
            ConanComponent conanComponent => conanComponent.ToSbomPackage(),
            CondaComponent condaComponent => condaComponent.ToSbomPackage(),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToSbomPackage(),
            GitComponent gitComponent => gitComponent.ToSbomPackage(),
            GoComponent goComponent => goComponent.ToSbomPackage(),
            LinuxComponent linuxComponent => linuxComponent.ToSbomPackage(),
            MavenComponent mavenComponent => mavenComponent.ToSbomPackage(component),
            NpmComponent npmComponent => npmComponent.ToSbomPackage(component),
            NuGetComponent nuGetComponent => nuGetComponent.ToSbomPackage(component),
            OtherComponent otherComponent => otherComponent.ToSbomPackage(),
            PipComponent pipComponent => pipComponent.ToSbomPackage(component),
            PodComponent podComponent => podComponent.ToSbomPackage(component),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToSbomPackage(component),
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
