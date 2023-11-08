// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Class responsible for taking the output of a component-detection scan and extracting additional information about the package based on its protocol.
/// </summary>
public class PackageDetailsFactory : IPackageDetailsFactory
{
    private readonly ILogger log;
    private readonly IMavenUtils mavenUtils;
    private readonly INugetUtils nugetUtils;

    public PackageDetailsFactory(ILogger log, IMavenUtils mavenUtils, INugetUtils nugetUtils)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.mavenUtils = mavenUtils ?? throw new ArgumentNullException(nameof(mavenUtils));
        this.nugetUtils = nugetUtils ?? throw new ArgumentNullException(nameof(nugetUtils));
    }

    public IDictionary<(string Name, string Version), PackageDetails> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents)
    {
        var packageDetailsLocations = GetPackageDetailsLocations(scannedComponents);

        return ExtractPackageDetailsFromFiles(packageDetailsLocations);
    }

    private List<string> GetPackageDetailsLocations(IEnumerable<ScannedComponent> scannedComponents)
    {
        var packageDetailsConfirmedLocations = new List<string>();

        foreach (var scannedComponent in scannedComponents)
        {
            var componentType = scannedComponent.Component.Type;

            switch (componentType)
            {
                case ComponentType.NuGet:
                    packageDetailsConfirmedLocations.Add(nugetUtils.GetNuspecLocation(scannedComponent));
                    break;
                case ComponentType.Maven:
                    packageDetailsConfirmedLocations.Add(mavenUtils.GetPomLocation(scannedComponent));
                    break;
                default:
                    break;
            }
        }

        return packageDetailsConfirmedLocations;
    }

    private IDictionary<(string Name, string Version), PackageDetails> ExtractPackageDetailsFromFiles(List<string> packageDetailsPaths)
    {
        // Create a var called packageDetailsDictionary where the key is a tuple of the package name and version and the value is a PackageDetailsObject
        var packageDetailsDictionary = new ConcurrentDictionary<(string, string), PackageDetails>();

        foreach (var path in packageDetailsPaths)
        {
            // If path ends in .nuspec then it is a nuspec file
            if (!string.IsNullOrEmpty(path) && path.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
            {
                var nuspecDetails = nugetUtils.ParseNuspec(path);
                packageDetailsDictionary.TryAdd((nuspecDetails.Name, nuspecDetails.Version), nuspecDetails.packageDetails);
            }

            if (!string.IsNullOrEmpty(path) && path.EndsWith(".pom", StringComparison.OrdinalIgnoreCase))
            {
                var pomDetails = mavenUtils.ParsePom(path);
                packageDetailsDictionary.TryAdd((pomDetails.Name, pomDetails.Version), pomDetails.packageDetails);
            }
        }

        log.Debug($"Found data in {packageDetailsDictionary.Count} components out of {packageDetailsPaths.Count} locations");

        return packageDetailsDictionary;
    }
}
