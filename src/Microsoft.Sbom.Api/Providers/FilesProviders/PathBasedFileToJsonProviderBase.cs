// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Providers.FilesProviders
{
    /// <summary>
    /// Abstract base class for all file path based providers. This assumes that we are getting a list of file
    /// paths to process as a string.
    /// </summary>
    public abstract class PathBasedFileToJsonProviderBase : EntityToJsonProviderBase<string>
    {
        public FileHasher FileHasher { get; }

        public ManifestFolderFilterer FileFilterer { get; }

        public FileInfoWriter FileHashWriter { get; }

        public InternalSBOMFileInfoDeduplicator InternalSBOMFileInfoDeduplicator { get; }

        public PathBasedFileToJsonProviderBase(
            IConfiguration configuration,
            ChannelUtils channelUtils,
            Serilog.ILogger log,
            FileHasher fileHasher,
            ManifestFolderFilterer fileFilterer,
            FileInfoWriter fileHashWriter,
            InternalSBOMFileInfoDeduplicator internalSBOMFileInfoDeduplicator)
            : base(configuration, channelUtils, log)
        {
            FileHasher = fileHasher ?? throw new ArgumentNullException(nameof(fileHasher));
            FileFilterer = fileFilterer ?? throw new ArgumentNullException(nameof(fileFilterer));
            FileHashWriter = fileHashWriter ?? throw new ArgumentNullException(nameof(fileHashWriter));
            InternalSBOMFileInfoDeduplicator = internalSBOMFileInfoDeduplicator ?? throw new ArgumentNullException(nameof(internalSBOMFileInfoDeduplicator));
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
            ConvertToJson(ChannelReader<string> sourceChannel, IList<ISbomConfig> requiredConfigs)
        {
            IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

            // Filter files
            var (filteredFiles, filteringErrors) = FileFilterer.FilterFiles(sourceChannel);
            errors.Add(filteringErrors);

            // Generate hash code for the files
            var (fileInfos, hashingErrors) = FileHasher.Run(filteredFiles);
            errors.Add(hashingErrors);
            fileInfos = InternalSBOMFileInfoDeduplicator.Deduplicate(fileInfos);

            var (jsonDocCount, jsonErrors) = FileHashWriter.Write(fileInfos, requiredConfigs);
            errors.Add(jsonErrors);

            return (jsonDocCount, ChannelUtils.Merge(errors.ToArray()));
        }
    }
}
