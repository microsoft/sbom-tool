// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Filter files that match various filter criteria from the channel stream.
/// </summary>
public class FileFilterer
{
    private readonly IFilter<DownloadedRootPathFilter> rootPathFilter;
    private readonly ILogger log;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IConfiguration configuration;

    public FileFilterer(
        IFilter<DownloadedRootPathFilter> rootPathFilter,
        ILogger log,
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils)
    {
        this.rootPathFilter = rootPathFilter ?? throw new ArgumentNullException(nameof(rootPathFilter));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public (ChannelReader<InternalSbomFileInfo> files, ChannelReader<FileValidationResult> errors) Filter(ChannelReader<InternalSbomFileInfo> files)
    {
        var output = Channel.CreateUnbounded<InternalSbomFileInfo>();
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

    private async Task FilterFiles(InternalSbomFileInfo file, Channel<FileValidationResult> errors, Channel<InternalSbomFileInfo> output)
    {
        try
        {
            // Resolve ../ in paths to absolute paths.
            var fullPath = Path.GetFullPath(fileSystemUtils.JoinPaths(configuration.BuildDropPath.Value, file.Path));

            // Filter SPDX type files.
            if (file.FileTypes != null && file.FileTypes.Contains(Contracts.Enums.FileType.SPDX))
            {
                // If the file is in the buildDropPath => validate it
                // If it's outside, throw referencedSBOMFile error.
                if (!fullPath.StartsWith(configuration.BuildDropPath.Value, StringComparison.InvariantCultureIgnoreCase))
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.ReferencedSbomFile,
                        Path = file.Path
                    });

                    return;
                }
            }

            // Filter paths that are not present on disk.
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
