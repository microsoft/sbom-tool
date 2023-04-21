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
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Providers.FilesProviders;

/// <summary>
/// Serializes a list of <see cref="SbomFile"/> objects provided through the API to SBOM Json objects.
/// </summary>
public class SbomFileBasedFileToJsonProvider : EntityToJsonProviderBase<SbomFile>
{
    private readonly FileInfoWriter fileHashWriter;

    private readonly SbomFileToFileInfoConverter sbomFileToFileInfoConverter;

    private readonly InternalSBOMFileInfoDeduplicator fileInfoDeduplicator;

    public SbomFileBasedFileToJsonProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger logger,
        FileInfoWriter fileHashWriter,
        SbomFileToFileInfoConverter sbomFileToFileInfoConverter,
        InternalSBOMFileInfoDeduplicator fileInfo)
        : base(configuration, channelUtils, logger)
    {
        this.fileHashWriter = fileHashWriter ?? throw new ArgumentNullException(nameof(fileHashWriter));
        this.sbomFileToFileInfoConverter = sbomFileToFileInfoConverter ?? throw new ArgumentNullException(nameof(sbomFileToFileInfoConverter));
        fileInfoDeduplicator = fileInfo ?? throw new ArgumentNullException(nameof(fileInfo));
    }

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
                Log.Debug($"Using the {nameof(SbomFileBasedFileToJsonProvider)} provider for the files workflow.");
                return true;
            }
        }

        return false;
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
        ConvertToJson(ChannelReader<SbomFile> sourceChannel, IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

        var (fileInfos, hashErrors) = sbomFileToFileInfoConverter.Convert(sourceChannel);
        errors.Add(hashErrors);
        fileInfos = fileInfoDeduplicator.Deduplicate(fileInfos);

        var (jsonDocCount, jsonErrors) = fileHashWriter.Write(fileInfos, requiredConfigs);
        errors.Add(jsonErrors);

        return (jsonDocCount, ChannelUtils.Merge(errors.ToArray()));
    }

    protected override (ChannelReader<SbomFile> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        var listWalker = new ListWalker<SbomFile>();
        return listWalker.GetComponents(Configuration.FilesList.Value);
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
        WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}