// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Uses the <see cref="IManifestGenerator"/> to write a json object that contains 
    /// a format specific representation of the <see cref="PackageInfo"/>.
    /// </summary>
    public class PackageInfoJsonWriter
    {
        private readonly ManifestGeneratorProvider manifestGeneratorProvider;
        private readonly ILogger log;

        public PackageInfoJsonWriter(
            ManifestGeneratorProvider manifestGeneratorProvider,
            ILogger log)
        {
            if (manifestGeneratorProvider is null)
            {
                throw new ArgumentNullException(nameof(manifestGeneratorProvider));
            }

            this.manifestGeneratorProvider = manifestGeneratorProvider;
            this.log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public (ChannelReader<JsonDocWithSerializer> result, ChannelReader<FileValidationResult> errors) Write(ChannelReader<SBOMPackage> packageInfos, IList<ISbomConfig> packagesArraySupportingConfigs)
        {
            var errors = Channel.CreateUnbounded<FileValidationResult>();
            var result = Channel.CreateUnbounded<JsonDocWithSerializer>();

            Task.Run(async () =>
            {
                await foreach (SBOMPackage packageInfo in packageInfos.ReadAllAsync())
                {
                    await GenerateJson(packagesArraySupportingConfigs, packageInfo, result, errors);
                }

                errors.Writer.Complete();
                result.Writer.Complete();
            });

            return (result, errors);
        }

        private async Task GenerateJson(IList<ISbomConfig> packagesArraySupportingConfigs, SBOMPackage packageInfo, Channel<JsonDocWithSerializer> result,
            Channel<FileValidationResult> errors)
        {
            try
            {
                foreach (ISbomConfig sbomConfig in packagesArraySupportingConfigs)
                {
                    var generationResult =
                        manifestGeneratorProvider.Get(sbomConfig.ManifestInfo).GenerateJsonDocument(packageInfo);
                    sbomConfig.Recorder.RecordPackageId(generationResult?.ResultMetadata?.EntityId);
                    await result.Writer.WriteAsync((generationResult?.Document, sbomConfig.JsonSerializer));
                }
            }
            catch (Exception e)
            {
                log.Debug($"Encountered an error while generating json for packageInfo {packageInfo}: {e.Message}");
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.JsonSerializationError,
                    Path = packageInfo.PackageName
                });
            }
        }
    }
}
