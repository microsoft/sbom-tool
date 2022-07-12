// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Adapters.ComponentDetection.Logging;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Adapters.ComponentDetection
{
    /// <summary>
    /// Extensions methods for <see cref="ScannedComponent"/>.
    /// </summary>
    public static class ScannedComponentExtensions
    {
        /// <summary>
        /// Converts a <see cref="ScannedComponent"/> to an <see cref="SBOMPackage"/>.
        /// </summary>
        public static SBOMPackage? ToSbomPackage(this ScannedComponent component, AdapterReport report)
        {
            return component.Component switch
            {
                CargoComponent cargoComponent => cargoComponent.ToSbomPackage(),
                CondaComponent condaComponent => condaComponent.ToSbomPackage(),
                DockerImageComponent dockerImageComponent => dockerImageComponent.ToSbomPackage(),
                GitComponent gitComponent => gitComponent.ToSbomPackage(),
                GoComponent goComponent => goComponent.ToSbomPackage(),
                LinuxComponent linuxComponent => linuxComponent.ToSbomPackage(),
                MavenComponent mavenComponent => mavenComponent.ToSbomPackage(),
                NpmComponent npmComponent => npmComponent.ToSbomPackage(),
                NuGetComponent nuGetComponent => nuGetComponent.ToSbomPackage(),
                OtherComponent otherComponent => otherComponent.ToSbomPackage(),
                PipComponent pipComponent => pipComponent.ToSbomPackage(),
                PodComponent podComponent => podComponent.ToSbomPackage(),
                RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToSbomPackage(),
                null => Error(report => report.LogNullComponent(nameof(ToSbomPackage))),
                _ => Error(report => report.LogNoConversionFound(component.Component.GetType(), component.Component))
            };

            // Logs an error prior to returning null.
            SBOMPackage? Error(Action<AdapterReport> log)
            {
                log(report);
                return null;
            }
        }
    }
}