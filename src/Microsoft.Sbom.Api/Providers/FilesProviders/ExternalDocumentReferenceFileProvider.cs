// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Providers.FilesProviders;

/// <summary>
/// Provider for external document reference file supported only when
/// ExternalDocumentReferenceListFile is provided in the generation arguments.
/// </summary>
public class ExternalDocumentReferenceFileProvider : PathBasedFileToJsonProviderBase
{
    private readonly FileListEnumerator listWalker;

    public ExternalDocumentReferenceFileProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger log,
        FileHasher fileHasher,
        ManifestFolderFilterer fileFilterer,
        FileInfoWriter fileHashWriter,
        InternalSBOMFileInfoDeduplicator internalSBOMFileInfoDeduplicator,
        FileListEnumerator listWalker)
        : base(configuration, channelUtils, log, fileHasher, fileFilterer, fileHashWriter, internalSBOMFileInfoDeduplicator)
    {
        this.listWalker = listWalker ?? throw new ArgumentNullException(nameof(listWalker));
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.Files && !string.IsNullOrWhiteSpace(Configuration.ExternalDocumentReferenceListFile?.Value))
        {
            Log.Debug($"Using the {nameof(ExternalDocumentReferenceFileProvider)} provider for the files workflow.");
            return true;
        }

        return false;
    }

    protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        if (Configuration.ExternalDocumentReferenceListFile?.Value == null)
        {
            var emptyList = Channel.CreateUnbounded<string>();
            emptyList.Writer.Complete();
            var errors = Channel.CreateUnbounded<FileValidationResult>();
            errors.Writer.Complete();
            return (emptyList, errors);
        }

        return listWalker.GetFilesFromList(Configuration.ExternalDocumentReferenceListFile.Value);
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}
