// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Filters;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Filters out folders for which we don't generate hashes, such as anything under the _manifest folder.
/// </summary>
public class ManifestFolderFilterer
{
    private readonly IFilter<ManifestFolderFilter> manifestFolderFilter;
    private readonly ILogger log;

    public ManifestFolderFilterer(
        IFilter<ManifestFolderFilter> manifestFolderFilter,
        ILogger log)
    {
        ArgumentNullException.ThrowIfNull(manifestFolderFilter);
        ArgumentNullException.ThrowIfNull(log);
        this.manifestFolderFilter = manifestFolderFilter;
        this.log = log;
    }

    public (ChannelReader<string> file, ChannelReader<FileValidationResult> errors) FilterFiles(ChannelReader<string> files)
    {
        var output = Channel.CreateUnbounded<string>();
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

    private async Task FilterFiles(string file, Channel<FileValidationResult> errors, Channel<string> output)
    {
        try
        {
            if (!manifestFolderFilter.IsValid(file))
            {
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.ManifestFolder,
                    Path = file
                });
            }
            else
            {
                await output.Writer.WriteAsync(file);
            }
        }
        catch (Exception e)
        {
            log.Warning("Encountered an error while filtering file {File}: {Message}", file, e.Message);
            await errors.Writer.WriteAsync(new FileValidationResult
            {
                ErrorType = ErrorType.Other,
                Path = file
            });
        }
    }
}
