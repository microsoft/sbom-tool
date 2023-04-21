// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Given a directory path, walks the subtree and returns all the 
/// files in the directory.
/// </summary>
public class DirectoryWalker
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;
    private readonly bool followSymlinks;

    public DirectoryWalker(IFileSystemUtils fileSystemUtils, ILogger log, IConfiguration configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));

        followSymlinks = configuration.FollowSymlinks?.Value ?? true;

        if (!followSymlinks)
        {
            log.Information("FollowSymlinks parameter is set to false, we won't follow symbolic links while traversing the filesystem.");
        }
    }

    public (ChannelReader<string> file, ChannelReader<FileValidationResult> errors) GetFilesRecursively(string root)
    {
        log.Debug($"Enumerating files under the root path {root}.");

        if (!fileSystemUtils.DirectoryExists(root))
        {
            throw new InvalidPathException($"The root path at {root} doesn't exist or is not accessible.");
        }

        var output = Channel.CreateUnbounded<string>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        async Task WalkDir(string path)
        {
            try
            {
                foreach (var file in fileSystemUtils.GetFilesInDirectory(path, followSymlinks))
                {
                    await output.Writer.WriteAsync(file);
                }

                var tasks = fileSystemUtils.GetDirectories(path, followSymlinks).Select(WalkDir);
                await Task.WhenAll(tasks.ToArray());
            }
            catch (Exception e)
            {
                log.Debug($"Encountered an unknown error for {path}: {e.Message}");
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.Other,
                    Path = path
                });
            }
        }

        Task.Run(async () =>
        {
            await WalkDir(root);
            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }
}