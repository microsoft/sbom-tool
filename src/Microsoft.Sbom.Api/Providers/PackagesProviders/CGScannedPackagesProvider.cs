// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Executors;
using Ninject;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;

namespace Microsoft.Sbom.Api.Providers.PackagesProviders
{
    /// <summary>
    /// Calls the component detector to get a list of packages in the current project and serializes them to Json.
    /// </summary>
    public class CGScannedPackagesProvider : CommonPackagesProvider<ScannedComponent>
    {
        [Inject]
        public ComponentToPackageInfoConverter PackageInfoConverter { get; set; }

        [Inject]
        public PackagesWalker PackagesWalker { get; set; }

        public override bool IsSupported(ProviderType providerType)
        {
            if (providerType == ProviderType.Packages)
            {
                if (Configuration.PackagesList?.Value == null)
                {
                    // If no other packages providers are present, use this one.
                    Log.Debug($"Using the {nameof(CGScannedPackagesProvider)} provider for the packages workflow.");
                    return true;
                }
            }

            return false;
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
            ConvertToJson(
                ChannelReader<ScannedComponent> sourceChannel,
                IList<ISbomConfig> requiredConfigs)
        {
            IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

            var (packageInfos, packageErrors) = PackageInfoConverter.Convert(sourceChannel);
            errors.Add(packageErrors);

            var (jsonResults, jsonErrors) = PackageInfoJsonWriter.Write(packageInfos, requiredConfigs);
            errors.Add(jsonErrors);

            return (jsonResults, ChannelUtils.Merge(errors.ToArray()));
        }

        protected override (ChannelReader<ScannedComponent> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            var (output, cdErrors) = PackagesWalker.GetComponents(Configuration.BuildComponentPath?.Value);

            if (cdErrors.TryRead(out ComponentDetectorException e))
            {
                throw e;
            }

            var errors = Channel.CreateUnbounded<FileValidationResult>();
            errors.Writer.Complete();
            return (output, errors);
        }
    }
}
