// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.ComponentDetection.Logging;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// Extensions methods for <see cref="ScannedComponentWithLicense"/>.
/// </summary>
public static class ScannedComponentExtensions
{
    /// <summary>
    /// Converts a <see cref="ScannedComponentWithLicense"/> to an <see cref="SbomPackage"/>.
    /// </summary>
    public static SbomPackage? ToSbomPackage(this ScannedComponentWithLicense component, AdapterReport report)
    {
        return component.Component switch
        {
            CargoComponent cargoComponent => cargoComponent.ToSbomPackage(component?.License),
            ConanComponent conanComponent => conanComponent.ToSbomPackage(),
            CondaComponent condaComponent => condaComponent.ToSbomPackage(),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToSbomPackage(),
            GitComponent gitComponent => gitComponent.ToSbomPackage(),
            GoComponent goComponent => goComponent.ToSbomPackage(),
            LinuxComponent linuxComponent => linuxComponent.ToSbomPackage(),
            MavenComponent mavenComponent => mavenComponent.ToSbomPackage(),
            NpmComponent npmComponent => npmComponent.ToSbomPackage(component?.License),
            NuGetComponent nuGetComponent => nuGetComponent.ToSbomPackage(component?.License),
            OtherComponent otherComponent => otherComponent.ToSbomPackage(),
            PipComponent pipComponent => pipComponent.ToSbomPackage(component?.License),
            PodComponent podComponent => podComponent.ToSbomPackage(component?.License),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToSbomPackage(component?.License),
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
