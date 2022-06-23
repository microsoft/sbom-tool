// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Ninject;
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
    /// Abstract base class for all file path based providers. This assumes that we are getting a list of file
    /// paths to process as a string.
    /// </summary>
    public abstract class PathBasedFileToJsonProviderBase : EntityToJsonProviderBase<string>
    {
        [Inject]
        public FileHasher FileHasher { get; set; }

        [Inject]
        public ManifestFolderFilterer FileFilterer { get; set; }

        [Inject]
        public FileInfoWriter FileHashWriter { get; set; }

        [Inject]
        public InternalSBOMFileInfoDeduplicator InternalSBOMFileInfoDeduplicator { get; set; }

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
