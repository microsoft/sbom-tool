using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using System;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    public class SPDXFileTypeFilterer
    {
        private readonly ILogger log;

        public SPDXFileTypeFilterer(ILogger log)
        {
            this.log = log;
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
                if (file.FileTypes != null && file.FileTypes.Contains(Contracts.Enums.FileType.SPDX))
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.ReferencedSbomFile,
                        Path = file.Path,
                    });
                }
                else
                {
                    await output.Writer.WriteAsync(file);
                }
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
