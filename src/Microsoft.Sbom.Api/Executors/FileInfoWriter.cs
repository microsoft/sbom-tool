// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Uses the <see cref="IManifestGenerator"/> to write a json object that contains
/// a file path and its associated hashes.
/// </summary>
public class FileInfoWriter
{
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly ILogger log;

    public FileInfoWriter(ManifestGeneratorProvider manifestGeneratorProvider, ILogger log)
    {
        if (manifestGeneratorProvider is null)
        {
            throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        }

        this.manifestGeneratorProvider = manifestGeneratorProvider;
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public (ChannelReader<JsonDocWithSerializer> result, ChannelReader<FileValidationResult> errors) Write(ChannelReader<InternalSbomFileInfo> fileInfos, IList<ISbomConfig> filesArraySupportingSboms)
    {
        var errors = Channel.CreateUnbounded<FileValidationResult>();
        var result = Channel.CreateUnbounded<JsonDocWithSerializer>();

        Task.Run(async () =>
        {
            await foreach (var fileInfo in fileInfos.ReadAllAsync())
            {
                await Generate(filesArraySupportingSboms, fileInfo, result, errors);
            }

            errors.Writer.Complete();
            result.Writer.Complete();
        });

        return (result, errors);
    }

    private async Task Generate(IList<ISbomConfig> filesArraySupportingSboms, InternalSbomFileInfo sbomFile, Channel<JsonDocWithSerializer> result, Channel<FileValidationResult> errors)
    {
        try
        {
            foreach (var config in filesArraySupportingSboms)
            {
                log.Verbose("Generating json for file {file} into {config}", sbomFile.Path, config.ManifestJsonFilePath);
                var generationResult = manifestGeneratorProvider
                    .Get(config.ManifestInfo)
                    .GenerateJsonDocument(sbomFile);

                var fileId = generationResult?.ResultMetadata?.EntityId;

                if (!sbomFile.IsOutsideDropPath)
                {
                    config.Recorder.RecordFileId(fileId);
                }

                if (sbomFile.FileTypes != null && sbomFile.FileTypes.Contains(Contracts.Enums.FileType.SPDX))
                {
                    config.Recorder.RecordSPDXFileId(fileId);
                }

                // Only include files in the files section if they are within the BuildDropPath
                // Files outside the BuildDropPath should only be processed as external document references
                if (!sbomFile.IsOutsideDropPath)
                {
                    await result.Writer.WriteAsync((generationResult?.Document, config.JsonSerializer));
                }
            }
        }
        catch (Exception e)
        {
            log.Warning($"Encountered an error while generating json for file {sbomFile.Path}: {e.Message}");
            await errors.Writer.WriteAsync(new FileValidationResult
            {
                ErrorType = ErrorType.JsonSerializationError,
                Path = sbomFile.Path
            });
        }
    }
}
