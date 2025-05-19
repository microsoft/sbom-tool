// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Serilog;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Class responsible for taking the output of a component-detection scan and extracting additional information about the package based on its protocol.
/// </summary>
public class PackageDetailsFactory : IPackageDetailsFactory
{
    private readonly ILogger log;
    private readonly IRecorder recorder;
    private readonly IPackageManagerUtils<MavenUtils> mavenUtils;
    private readonly IPackageManagerUtils<NugetUtils> nugetUtils;
    private readonly IPackageManagerUtils<RubyGemsUtils> rubygemUtils;

    public PackageDetailsFactory(ILogger log, IRecorder recorder, IPackageManagerUtils<MavenUtils> mavenUtils, IPackageManagerUtils<NugetUtils> nugetUtils, IPackageManagerUtils<RubyGemsUtils> rubygemUtils)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.mavenUtils = mavenUtils ?? throw new ArgumentNullException(nameof(mavenUtils));
        this.nugetUtils = nugetUtils ?? throw new ArgumentNullException(nameof(nugetUtils));
        this.rubygemUtils = rubygemUtils ?? throw new ArgumentNullException(nameof(rubygemUtils));
    }

    public IDictionary<(string Name, string Version), PackageDetails> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents)
    {
        using (recorder.TraceEvent(Events.SbomParseMetadata))
        {
            var packageDetailsLocations = GetPackageDetailsLocations(scannedComponents);

            return ExtractPackageDetailsFromFiles(packageDetailsLocations);
        }
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
                    packageDetailsConfirmedLocations.Add(nugetUtils.GetMetadataLocation(scannedComponent));
                    break;
                case ComponentType.Maven:
                    packageDetailsConfirmedLocations.Add(mavenUtils.GetMetadataLocation(scannedComponent));
                    break;
                case ComponentType.RubyGems:
                    packageDetailsConfirmedLocations.Add(rubygemUtils.GetMetadataLocation(scannedComponent));
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
            if (!string.IsNullOrEmpty(path))
            {
                switch (Path.GetExtension(path)?.ToLowerInvariant())
                {
                    case ".nuspec":
                        var nuspecDetails = nugetUtils.ParseMetadata(path);
                        if (!string.IsNullOrEmpty(nuspecDetails?.PackageDetails.License) || !string.IsNullOrEmpty(nuspecDetails?.PackageDetails?.Supplier))
                        {
                            packageDetailsDictionary.TryAdd((nuspecDetails.Name, nuspecDetails.Version), nuspecDetails.PackageDetails);
                        }

                        break;
                    case ".pom":
                        var pomDetails = mavenUtils.ParseMetadata(path);
                        if (!string.IsNullOrEmpty(pomDetails?.PackageDetails?.License) || !string.IsNullOrEmpty(pomDetails?.PackageDetails?.Supplier))
                        {
                            packageDetailsDictionary.TryAdd((pomDetails.Name, pomDetails.Version), pomDetails.PackageDetails);
                        }

                        break;
                    case ".gemspec":
                        var gemspecDetails = rubygemUtils.ParseMetadata(path);
                        if (!string.IsNullOrEmpty(gemspecDetails?.PackageDetails?.License) || !string.IsNullOrEmpty(gemspecDetails?.PackageDetails?.Supplier))
                        {
                            packageDetailsDictionary.TryAdd((gemspecDetails.Name, gemspecDetails.Version), gemspecDetails.PackageDetails);
                        }

                        break;
                    default:
                        log.Verbose("File extension {Extension} is not supported for extracting supplier info.", Path.GetExtension(path));
                        break;
                }
            }
        }

        if (packageDetailsPaths.Count > 0)
        {
            log.Information("Found additional information for {PackageCount} components out of {PathCount} supported components.", packageDetailsDictionary.Count, packageDetailsPaths.Count);
        }

        recorder.AddToTotalNumberOfPackageDetailsEntries(packageDetailsDictionary.Count);

        return packageDetailsDictionary;
    }
}
