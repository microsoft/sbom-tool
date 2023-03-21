// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Uses the <see cref="IManifestGenerator"/> to write a json object that contains 
    /// a file path and its associated hashes.
    /// </summary>
    public class FileInfoWriter
    {
        private readonly ManifestGeneratorProvider manifestGeneratorProvider;
        private readonly ILogger log;
        private readonly IFileSystemUtilsExtension fileSystemUtilsExtension;
        private readonly IConfiguration configuration;

        public FileInfoWriter(
            ManifestGeneratorProvider manifestGeneratorProvider,
            ILogger log,
            IFileSystemUtilsExtension fileSystemUtilsExtension,
            IConfiguration configuration)
        {
            if (manifestGeneratorProvider is null)
            {
                throw new ArgumentNullException(nameof(manifestGeneratorProvider));
            }

            this.manifestGeneratorProvider = manifestGeneratorProvider;
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.fileSystemUtilsExtension = fileSystemUtilsExtension ?? throw new ArgumentNullException(nameof(fileSystemUtilsExtension));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public (ChannelReader<JsonDocWithSerializer> result, ChannelReader<FileValidationResult> errors) Write(ChannelReader<InternalSBOMFileInfo> fileInfos, IList<ISbomConfig> filesArraySupportingSBOMs)
        {
            var errors = Channel.CreateUnbounded<FileValidationResult>();
            var result = Channel.CreateUnbounded<JsonDocWithSerializer>();

            Task.Run(async () =>
            {
                await foreach (InternalSBOMFileInfo fileInfo in fileInfos.ReadAllAsync())
                {
                    await Generate(filesArraySupportingSBOMs, fileInfo, result, errors);
                }

                errors.Writer.Complete();
                result.Writer.Complete();
            });

            return (result, errors);
        }

        private async Task Generate(IList<ISbomConfig> filesArraySupportingSBOMs, InternalSBOMFileInfo sbomFile, Channel<JsonDocWithSerializer> result, Channel<FileValidationResult> errors)
        {
            try
            {
                foreach (var config in filesArraySupportingSBOMs)
                {
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

                    await result.Writer.WriteAsync((generationResult?.Document, config.JsonSerializer));
                }
            }
            catch (Exception e)
            {
                log.Debug($"Encountered an error while generating json for file {sbomFile.Path}: {e.Message}");
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.JsonSerializationError,
                    Path = sbomFile.Path
                });
            }
        }
    }
}
