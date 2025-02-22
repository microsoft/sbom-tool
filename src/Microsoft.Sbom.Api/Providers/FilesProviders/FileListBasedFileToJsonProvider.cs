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
/// Takes in a list of files provided in a text file and only serializes those files.
/// The files in the list should be present on the disk and should be inside the build drop folder.
/// </summary>
public class FileListBasedFileToJsonProvider : PathBasedFileToJsonProviderBase
{
    private readonly FileListEnumerator listWalker;

    public FileListBasedFileToJsonProvider(IConfiguration configuration, ChannelUtils channelUtils, ILogger log, FileHasher fileHasher, ManifestFolderFilterer fileFilterer, FileInfoWriter fileHashWriter, InternalSbomFileInfoDeduplicator internalSBOMFileInfoDeduplicator, FileListEnumerator listWalker)
        : base(configuration, channelUtils, log, fileHasher, fileFilterer, fileHashWriter, internalSBOMFileInfoDeduplicator)
    {
        this.listWalker = listWalker ?? throw new ArgumentNullException(nameof(listWalker));
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.Files)
        {
            // Return true only if the BuildListFile parameter is provided.
            if (!string.IsNullOrWhiteSpace(Configuration.BuildListFile?.Value))
            {
                Log.Debug($"Using the {nameof(FileListBasedFileToJsonProvider)} provider for the files workflow.");
                return true;
            }
        }

        return false;
    }

    protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        return listWalker.GetFilesFromList(Configuration.BuildListFile.Value);
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}
