using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{ 
    public class HashValidator2
    {
        private readonly IConfiguration configuration;
        private readonly FileHashesDictionary fileHashesDictionary;

        public HashValidator2(IConfiguration configuration, FileHashesDictionary fileHashesDictionary)
        {
            this.configuration = configuration;
            this.fileHashesDictionary = fileHashesDictionary;
        }

        public (ChannelReader<FileValidationResult> output, ChannelReader<FileValidationResult> errors)
            Validate(ChannelReader<InternalSBOMFileInfo> fileWithHash)
        {
            var output = Channel.CreateUnbounded<FileValidationResult>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                await foreach (var fileHash in fileWithHash.ReadAllAsync())
                {
                    await Validate(fileHash, output, errors);
                }

                output.Writer.Complete();
                errors.Writer.Complete();
            });

            return (output, errors);
        }

        private async Task Validate(InternalSBOMFileInfo internalFileInfo, Channel<FileValidationResult> output, Channel<FileValidationResult> errors)
        {
            var sha256Checksum = internalFileInfo.Checksum.Where(c => c.Algorithm == AlgorithmName.SHA256).FirstOrDefault();
            var fileHashes = new FileHashes();
            fileHashes.SetHash(internalFileInfo.FileLocation, sha256Checksum);

            var newValue = fileHashesDictionary.FileHashes.AddOrUpdate(internalFileInfo.Path, fileHashes, (key, oldValue) =>
            {
                if (oldValue.GetHash(internalFileInfo.FileLocation) != null)
                {
                    throw new Exception($"Duplicate file found in {internalFileInfo.FileLocation} file: {internalFileInfo.Path}.");
                }

                oldValue.SetHash(internalFileInfo.FileLocation, sha256Checksum);
                return oldValue;
            });

            if (newValue.FileLocation == Sbom.Entities.FileLocation.All)
            {
                if (newValue.OnDiskHash == newValue.SBOMFileHash)
                {
                    await output.Writer.WriteAsync(new FileValidationResult { Path = internalFileInfo.Path });
                }
                else
                {
                    await errors.Writer.WriteAsync(new FileValidationResult { Path = internalFileInfo.Path, ErrorType = Entities.ErrorType.InvalidHash });
                }
            }
        }
    }
}
