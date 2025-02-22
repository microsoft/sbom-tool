// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers.FilesProviders;

/// <summary>
/// Abstract base class for all file path based providers. This assumes that we are getting a list of file
/// paths to process as a string.
/// </summary>
public abstract class PathBasedFileToJsonProviderBase : EntityToJsonProviderBase<string>
{
    private readonly FileHasher fileHasher;

    private readonly ManifestFolderFilterer fileFilterer;

    private readonly FileInfoWriter fileHashWriter;

    private readonly InternalSbomFileInfoDeduplicator internalSBOMFileInfoDeduplicator;

    public PathBasedFileToJsonProviderBase(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        Serilog.ILogger log,
        FileHasher fileHasher,
        ManifestFolderFilterer fileFilterer,
        FileInfoWriter fileHashWriter,
        InternalSbomFileInfoDeduplicator internalSBOMFileInfoDeduplicator)
        : base(configuration, channelUtils, log)
    {
        this.fileHasher = fileHasher ?? throw new ArgumentNullException(nameof(fileHasher));
        this.fileFilterer = fileFilterer ?? throw new ArgumentNullException(nameof(fileFilterer));
        this.fileHashWriter = fileHashWriter ?? throw new ArgumentNullException(nameof(fileHashWriter));
        this.internalSBOMFileInfoDeduplicator = internalSBOMFileInfoDeduplicator ?? throw new ArgumentNullException(nameof(internalSBOMFileInfoDeduplicator));
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
        ConvertToJson(ChannelReader<string> sourceChannel, IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

        // Filter files
        var (filteredFiles, filteringErrors) = fileFilterer.FilterFiles(sourceChannel);
        errors.Add(filteringErrors);

        // Generate hash code for the files
        var (fileInfos, hashingErrors) = fileHasher.Run(filteredFiles);
        errors.Add(hashingErrors);
        var deduplicatedFileInfos = internalSBOMFileInfoDeduplicator.Deduplicate(fileInfos);

        var (jsonDocCount, jsonErrors) = fileHashWriter.Write(deduplicatedFileInfos, requiredConfigs);
        errors.Add(jsonErrors);

        return (jsonDocCount, ChannelUtils.Merge(errors.ToArray()));
    }
}
