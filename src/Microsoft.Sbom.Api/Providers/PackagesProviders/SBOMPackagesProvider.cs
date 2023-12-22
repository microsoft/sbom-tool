// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers.PackagesProviders;

/// <summary>
/// Provides a serialized list of packages given a list of <see cref="SbomPackage"/>.
/// </summary>
public class SBOMPackagesProvider : CommonPackagesProvider<SbomPackage>
{
    public SBOMPackagesProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger<SBOMPackagesProvider> logger,
        ISbomConfigProvider sbomConfigs,
        PackageInfoJsonWriter packageInfoJsonWriter,
        ILicenseInformationFetcher licenseInformationFetcher)
        : base(configuration, channelUtils, logger, sbomConfigs, packageInfoJsonWriter, licenseInformationFetcher)
    {
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.Packages)
        {
            if (Configuration.PackagesList?.Value != null)
            {
                Log.LogDebug($"Using the {nameof(SBOMPackagesProvider)} provider for the packages workflow.");
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
        var listWalker = new ListWalker<SbomPackage>();
        return listWalker.GetComponents(Configuration.PackagesList.Value);
    }
}
