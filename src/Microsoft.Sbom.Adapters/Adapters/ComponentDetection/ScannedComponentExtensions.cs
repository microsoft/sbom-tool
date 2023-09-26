// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.ComponentDetection.Logging;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

/// <summary>
/// Extensions methods for <see cref="ScannedComponentWithLicense" />.
/// </summary>
public static class ScannedComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="ScannedComponentWithLicense" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="component">The <see cref="ScannedComponentWithLicense" /> to convert.</param>
    /// <param name="report">The <see cref="AdapterReport" /> to use for logging.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public static SbomPackage? ToSbomPackage(this ScannedComponentWithLicense component, AdapterReport report)
    {
        return component.Component switch
        {
            CargoComponent cargoComponent => cargoComponent.ToSbomPackage(component.License),
            CondaComponent condaComponent => condaComponent.ToSbomPackage(),
            ConanComponent conanComponent => conanComponent.ToSbomPackage(component.License),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToSbomPackage(),
            GitComponent gitComponent => gitComponent.ToSbomPackage(),
            GoComponent goComponent => goComponent.ToSbomPackage(),
            LinuxComponent linuxComponent => linuxComponent.ToSbomPackage(),
            MavenComponent mavenComponent => mavenComponent.ToSbomPackage(),
            NpmComponent npmComponent => npmComponent.ToSbomPackage(component.License),
            NuGetComponent nuGetComponent => nuGetComponent.ToSbomPackage(component.License),
            OtherComponent otherComponent => otherComponent.ToSbomPackage(),
            PipComponent pipComponent => pipComponent.ToSbomPackage(component.License),
            PodComponent podComponent => podComponent.ToSbomPackage(component.License),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToSbomPackage(component.License),
            null => Error(log => log.LogNullComponent(nameof(ToSbomPackage))),
            _ => Error(log => log.LogNoConversionFound(component.Component.GetType(), component.Component)),
        };

        // Logs an error prior to returning null.
        SbomPackage? Error(Action<AdapterReport> log)
        {
            log(report);
            return null;
        }
    }
}
