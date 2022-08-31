// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Contracts;

using Microsoft.Sbom.Api.Config;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Given a list of <see cref="FileInfo"/> objects, and a <see cref="ManifestData"/>
    /// object, validates if the file hash matches the hash provided in the manifest data.
    /// 
    /// Used only in the Validation action.
    /// </summary>
    public class HashValidator
    {
        private readonly ManifestData manifestData;
        private readonly IConfiguration configuration;

        public HashValidator(IConfiguration configuration, ManifestData manifestData)
        {
            this.configuration = configuration;
            this.manifestData = manifestData;
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

        private async Task Validate(InternalSBOMFileInfo fileHash, Channel<FileValidationResult> output, Channel<FileValidationResult> errors)
        {
            var result = new FileValidationResult
            {
                Path = fileHash.Path
            };

            if (manifestData.HashesMap.TryGetValue(fileHash.Path, out Checksum[] expectedHashes))
            {
                manifestData.HashesMap.Remove(fileHash.Path);

                var expectedHash = expectedHashes
                    .Where(e => e.Algorithm == configuration.HashAlgorithm.Value)
                    .Select(e => e.ChecksumValue).First();
                var actualHash = fileHash.Checksum
                    .Where(e => e.Algorithm == configuration.HashAlgorithm.Value)
                    .Select(e => e.ChecksumValue).First();

                if (expectedHash == actualHash)
                {
                    result.ErrorType = ErrorType.None;
                    await output.Writer.WriteAsync(result);
                }
                else
                {
                    result.ErrorType = ErrorType.InvalidHash;
                    await errors.Writer.WriteAsync(result);
                }
            }
            else
            {
                result.ErrorType = ErrorType.AdditionalFile;
                await errors.Writer.WriteAsync(result);
            }
        }
    }
}
