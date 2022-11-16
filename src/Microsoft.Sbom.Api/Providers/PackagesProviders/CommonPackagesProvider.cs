// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config;
using Serilog;
using System;

namespace Microsoft.Sbom.Api.Providers.PackagesProviders
{
    /// <summary>
    /// Abstract base class for all packages providers. Provides a list of common packages to be serialized
    /// for every SBOM format.
    /// </summary>
    public abstract class CommonPackagesProvider<T> : EntityToJsonProviderBase<T>
    {
        public ISbomConfigProvider SBOMConfigs { get; }

        public PackageInfoJsonWriter PackageInfoJsonWriter { get; }

        protected CommonPackagesProvider(
            IConfiguration configuration,
            ChannelUtils channelUtils,
            ILogger logger,
            ISbomConfigProvider sbomConfigs,
            PackageInfoJsonWriter packageInfoJsonWriter)
            : base(configuration, channelUtils, logger)
        {
            SBOMConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
            PackageInfoJsonWriter = packageInfoJsonWriter ?? throw new ArgumentNullException(nameof(packageInfoJsonWriter));
        }

        /// <summary>
        /// Get common packages that are provided by the build engine.
        /// </summary>
        /// <returns></returns>
        private Channel<SBOMPackage> GetCommonPackages()
        {
            var packageInfos = Channel.CreateUnbounded<SBOMPackage>();

            Task.Run(async () =>
            {
                try
                {
                    if (SBOMConfigs.TryGetMetadata(MetadataKey.ImageOS, out object imageOsObj) &&
                        SBOMConfigs.TryGetMetadata(MetadataKey.ImageVersion, out object imageVersionObj))
                    {
                        Log.Debug($"Adding the image OS package to the packages list as a dependency.");
                        string name = $"Azure Pipelines Hosted Image {imageOsObj}";
                        await packageInfos.Writer.WriteAsync(new SBOMPackage()
                        {
                            PackageName = name,
                            PackageVersion = (string)imageVersionObj,
                            PackageUrl = "https://github.com/actions/virtual-environments",
                            Id = $"{name} {(string)imageVersionObj}".Replace(' ', '-'),
                            Supplier = "Microsoft/GitHub"
                        });
                    }
                }
                finally
                {
                    packageInfos.Writer.Complete();
                }
            });

            return packageInfos;
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
            WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
        {
            return PackageInfoJsonWriter.Write(GetCommonPackages(), requiredConfigs);
        }
    }
}
