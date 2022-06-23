﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Ninject;
using Microsoft.Sbom.Contracts;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers.FilesProviders
{
    /// <summary>
    /// Serializes a list of <see cref="SBOMFile"/> objects provided through the API to SBOM Json objects.
    /// </summary>
    public class SBOMFileBasedFileToJsonProvider : EntityToJsonProviderBase<SBOMFile>
    {
        /// <summary>
        /// Gets or sets serializes a <see cref="FileInfo"/> object to Json.
        /// </summary>
        [Inject]
        public FileInfoWriter FileHashWriter { get; set; }

        /// <summary>
        /// Gets or sets converts a <see cref="SBOMFile"/> object to a <see cref="FileInfo"/>.
        /// </summary>
        [Inject]
        public SBOMFileToFileInfoConverter SBOMFileToFileInfoConverter { get; set; }

        /// <summary>
        /// Gets or sets deduplicate FileInfo due to duplications of other providers.
        /// </summary>
        [Inject]
        public InternalSBOMFileInfoDeduplicator FileInfoDeduplicator { get; set; }

        /// <summary>
        /// Returns true only if the fileslist parameter is provided.
        /// </summary>
        /// <param name="providerType"></param>
        /// <returns></returns>
        public override bool IsSupported(ProviderType providerType)
        {
            if (providerType == ProviderType.Files)
            {
                if (Configuration.FilesList?.Value != null && string.IsNullOrWhiteSpace(Configuration.BuildListFile?.Value))
                {
                    Log.Debug($"Using the {nameof(SBOMFileBasedFileToJsonProvider)} provider for the files workflow.");
                    return true;
                }
            }

            return false;
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
            ConvertToJson(ChannelReader<SBOMFile> sourceChannel, IList<ISbomConfig> requiredConfigs)
        {
            IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

            var (fileInfos, hashErrors) = SBOMFileToFileInfoConverter.Convert(sourceChannel);
            errors.Add(hashErrors);
            fileInfos = FileInfoDeduplicator.Deduplicate(fileInfos);

            var (jsonDocCount, jsonErrors) = FileHashWriter.Write(fileInfos, requiredConfigs);
            errors.Add(jsonErrors);

            return (jsonDocCount, ChannelUtils.Merge(errors.ToArray()));
        }

        protected override (ChannelReader<SBOMFile> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            var listWalker = new ListWalker<SBOMFile>();
            return listWalker.GetComponents(Configuration.FilesList.Value);
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
            WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
        {
            return (null, null);
        }
    }
}
