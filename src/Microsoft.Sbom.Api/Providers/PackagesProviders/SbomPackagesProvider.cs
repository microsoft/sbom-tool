// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Providers.PackagesProviders;

/// <summary>
/// Provides a serialized list of packages given a list of <see cref="SbomPackage"/>.
/// </summary>
public class SbomPackagesProvider : CommonPackagesProvider<SbomPackage>
{
    private readonly ISbomConfigProvider sbomConfigs;

    public SbomPackagesProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger logger,
        ISbomConfigProvider sbomConfigs,
        PackageInfoJsonWriter packageInfoJsonWriter,
        IPackageDetailsFactory packageDetailsFactory,
        ILicenseInformationFetcher licenseInformationFetcher)
        : base(configuration, channelUtils, logger, sbomConfigs, packageInfoJsonWriter, packageDetailsFactory, licenseInformationFetcher)
    {
        // These are already checked for null in the base class constructor.
        this.sbomConfigs = sbomConfigs;
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.Packages)
        {
            if (Configuration.PackagesList?.Value != null)
            {
                Log.Debug($"Using the {nameof(SbomPackagesProvider)} provider for the packages workflow.");
                return true;
            }
        }

        return false;
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) ConvertToJson(ChannelReader<SbomPackage> sourceChannel, IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();
        var (jsonDocCount, jsonErrors) = PackageInfoJsonWriter.Write(sourceChannel, requiredConfigs);
        errors.Add(jsonErrors);

        return (jsonDocCount, ChannelUtils.Merge(errors.ToArray()));
    }

    protected override (ChannelReader<SbomPackage> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        if (Configuration.ManifestToolAction == ManifestToolActions.Aggregate)
        {
            if (Configuration.PackageDependenciesList?.Value is null)
            {
                Log.Error("Package dependencies list is null. Cannot proceed with package provider.");
            }
            else
            {
                foreach (var manifestInfo in Configuration.ManifestInfo.Value)
                {
                    if (sbomConfigs.TryGet(manifestInfo, out var sbomConfig))
                    {
                        foreach (var pair in Configuration.PackageDependenciesList.Value)
                        {
                            sbomConfig.Recorder?.RecordPackageId(pair.Key, pair.Value);
                        }
                    }
                }
            }
        }

        var listWalker = new ListWalker<SbomPackage>();
        return listWalker.GetComponents(Configuration.PackagesList.Value);
    }
}
