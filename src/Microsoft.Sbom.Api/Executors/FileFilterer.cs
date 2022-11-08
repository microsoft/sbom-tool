// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Ninject;
using Serilog;
using System;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    public class FileFilterer
    {
        private readonly IFilter rootPathFilter;
        private readonly ILogger log;
        private readonly IFileSystemUtils fileSystemUtils;
        private readonly IConfiguration configuration;

        public FileFilterer(
            [Named(nameof(DownloadedRootPathFilter))] IFilter rootPathFilter,
            ILogger log,
            IConfiguration configuration,
            IFileSystemUtils fileSystemUtils)
        {
            this.rootPathFilter = rootPathFilter ?? throw new ArgumentNullException(nameof(rootPathFilter));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        public (ChannelReader<InternalSBOMFileInfo> files, ChannelReader<FileValidationResult> errors) FilterSPDXFiles(ChannelReader<InternalSBOMFileInfo> files)
        {
            var output = Channel.CreateUnbounded<InternalSBOMFileInfo>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                await foreach (var file in files.ReadAllAsync())
                {
                    await FilterFiles(file, errors, output);
                }

                output.Writer.Complete();
                errors.Writer.Complete();
            });

            return (output, errors);
        }

        private async Task FilterFiles(InternalSBOMFileInfo file, Channel<FileValidationResult> errors, Channel<InternalSBOMFileInfo> output)
        {
            try
            {
                // Filter SPDX type files.
                if (file.FileTypes != null && file.FileTypes.Contains(Contracts.Enums.FileType.SPDX))
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.ReferencedSbomFile,
                        Path = file.Path,
                    });

                    return;
                }

                // Filter paths that are not present on disk.
                var fullPath = fileSystemUtils.JoinPaths(configuration.BuildDropPath.Value, file.Path);
                if (!rootPathFilter.IsValid(fullPath))
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.FilteredRootPath,
                        Path = file.Path
                    });

                    return;
                }

                await output.Writer.WriteAsync(file);
                
            }
            catch (Exception e)
            {
                log.Debug($"Encountered an error while filtering file {file.Path}: {e.Message}");
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.Other,
                    Path = file.Path,
                });
            }
        }
    }
}
