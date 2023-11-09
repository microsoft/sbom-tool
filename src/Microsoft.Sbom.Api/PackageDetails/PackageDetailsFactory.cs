// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Output.Telemetry;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Class responsible for taking the output of a component-detection scan and extracting additional information about the package based on its protocol.
/// </summary>
public class PackageDetailsFactory : IPackageDetailsFactory
{
    private readonly ILogger log;
    private readonly IRecorder recorder;
    private readonly IMavenUtils mavenUtils;
    private readonly INugetUtils nugetUtils;

    public PackageDetailsFactory(ILogger log, IRecorder recorder, IMavenUtils mavenUtils, INugetUtils nugetUtils)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
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
        var packageDetailsDictionary = new ConcurrentDictionary<(string, string), PackageDetails>();

        foreach (var path in packageDetailsPaths)
        {
            switch (Path.GetExtension(path)?.ToLowerInvariant())
            {
                case ".nuspec" when !string.IsNullOrEmpty(path):
                    var nuspecDetails = nugetUtils.ParseNuspec(path);
                    if (!string.IsNullOrEmpty(nuspecDetails.packageDetails.License) || !string.IsNullOrEmpty(nuspecDetails.packageDetails.Supplier))
                    {
                        packageDetailsDictionary.TryAdd((nuspecDetails.Name, nuspecDetails.Version), nuspecDetails.packageDetails);
                    }

                    break;
                case ".pom" when !string.IsNullOrEmpty(path):
                    var pomDetails = mavenUtils.ParsePom(path);
                    if (!string.IsNullOrEmpty(pomDetails.packageDetails.License) || !string.IsNullOrEmpty(pomDetails.packageDetails.Supplier))
                    {
                        packageDetailsDictionary.TryAdd((pomDetails.Name, pomDetails.Version), pomDetails.packageDetails);
                    }

                    break;
                default:
                    break;
            }
        }

        if (packageDetailsPaths.Count > 0)
        {
            log.Information($"Found additional information for {packageDetailsDictionary.Count} components out of {packageDetailsPaths.Count} supported components.");
        }

        recorder.AddToTotalNumberOfPackageDetailsEntries(packageDetailsDictionary.Count);

        return packageDetailsDictionary;
    }
}
