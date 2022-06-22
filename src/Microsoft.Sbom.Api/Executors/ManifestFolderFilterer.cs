// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Ninject;
using Serilog;
using System;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Filters;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Filters out folders for which we don't generate hashes, such as anything under the _manifest folder.
    /// </summary>
    public class ManifestFolderFilterer
    {
        private readonly IFilter manifestFolderFilter;
        private readonly ILogger log;

        public ManifestFolderFilterer(
                                      [Named(nameof(ManifestFolderFilter))] IFilter manifestFolderFilter,
                                      ILogger log)
        {
            this.manifestFolderFilter = manifestFolderFilter ?? throw new ArgumentNullException(nameof(manifestFolderFilter));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public (ChannelReader<string> file, ChannelReader<FileValidationResult> errors) FilterFiles(ChannelReader<string> files)
        {
            var output = Channel.CreateUnbounded<string>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {

                await foreach (string file in files.ReadAllAsync())
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
                log.Debug($"Encountered an error while filtering file {file}: {e.Message}");
                await errors.Writer.WriteAsync(new FileValidationResult
                {
                    ErrorType = ErrorType.Other,
                    Path = file
                });
            }
        }
    }
}
