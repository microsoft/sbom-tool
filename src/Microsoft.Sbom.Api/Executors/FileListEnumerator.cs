// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Takes a data file containing a list of files and enumerates each file in the list.
/// The files should be present on the disk.
/// </summary>
public class FileListEnumerator
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger log;

    /// <summary>
    /// FileListEnumerator constructor for dependency injection.
    /// </summary>
    /// <param name="fileSystemUtils">IFileSystemUtils interface used for this instance.</param>
    /// <param name="log">Ilogger interface used for this instance.</param>
    public FileListEnumerator(IFileSystemUtils fileSystemUtils, ILogger log)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    /// <summary>
    /// Reads a list file which is a text file containing one full file path per line, validates the file
    /// exists and adds the file to the output stream.
    /// </summary>
    /// <param name="listFile">Full file path to the list file to read.</param>
    /// <returns></returns>
    public (ChannelReader<string> file, ChannelReader<FileValidationResult> errors) GetFilesFromList(string listFile)
    {
        if (string.IsNullOrWhiteSpace(listFile))
        {
            throw new ArgumentException($"'{nameof(listFile)}' cannot be null or whitespace.", nameof(listFile));
        }

        log.Debug($"Enumerating all files from {nameof(listFile)}.");

        if (!fileSystemUtils.FileExists(listFile))
        {
            throw new InvalidPathException($"The list file {listFile} doesn't exist or is not accessible.");
        }

        var output = Channel.CreateUnbounded<string>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        async Task ProcessLines(string file)
        {
            string allText = null;
            try
            {
                allText = fileSystemUtils.ReadAllText(file);
            }
            catch (Exception)
            {
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.Other,
                    Path = file
                });
            }

            // Split on Environment.NewLine and discard blank lines.
            var separator = new string[] { Environment.NewLine };
            var files = allText.Split(separator, StringSplitOptions.None)
                .Where(t => !string.IsNullOrEmpty(t));
            foreach (var oneFile in files)
            {
                try
                {
                    var absoluteFileName = fileSystemUtils.AbsolutePath(oneFile);
                    if (!fileSystemUtils.FileExists(absoluteFileName))
                    {
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.MissingFile,
                            Path = absoluteFileName
                        });
                    }
                    else
                    {
                        await output.Writer.WriteAsync(absoluteFileName);
                    }
                }
                catch (Exception)
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.Other,
                        Path = oneFile
                    });
                }
            }
        }

        Task.Run(async () =>
        {
            await ProcessLines(listFile);
            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }
}
