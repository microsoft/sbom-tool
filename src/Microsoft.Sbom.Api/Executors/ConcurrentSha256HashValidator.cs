// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Validates hashes from multiple file locations (on disk and inside SBOM) simulatenously using
/// a conncurrent dictionary.
/// </summary>
public class ConcurrentSha256HashValidator
{
    private readonly FileHashesDictionary fileHashesDictionary;
    private readonly IConfiguration configuration;

    public ConcurrentSha256HashValidator(FileHashesDictionary fileHashesDictionary, IConfiguration configuration)
    {
        this.fileHashesDictionary = fileHashesDictionary ?? throw new ArgumentNullException(nameof(fileHashesDictionary));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    private AlgorithmName HashAlgorithmName => configuration.HashAlgorithm?.Value ?? AlgorithmName.SHA256;

    public (ChannelReader<FileValidationResult> output, ChannelReader<FileValidationResult> errors)
        Validate(ChannelReader<InternalSbomFileInfo> fileWithHash)
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

    private async Task Validate(InternalSbomFileInfo internalFileInfo, Channel<FileValidationResult> output, Channel<FileValidationResult> errors)
    {
        var checksum = internalFileInfo.Checksum.FirstOrDefault(c => c.Algorithm == HashAlgorithmName);
        var fileHashes = new FileHashes();
        fileHashes.SetHash(internalFileInfo.FileLocation, checksum);
        FileValidationResult failureResult = null;

        var newValue = fileHashesDictionary.FileHashes.AddOrUpdate(internalFileInfo.Path, fileHashes, (key, oldValue) =>
        {
            // This means a file with the same location was already added to the dictionary.
            if (oldValue?.GetHash(internalFileInfo.FileLocation) != null)
            {
                failureResult = new FileValidationResult
                {
                    ErrorType = Entities.ErrorType.AdditionalFile,
                    Path = internalFileInfo.Path
                };

                return null;
            }

            oldValue?.SetHash(internalFileInfo.FileLocation, checksum);
            return oldValue;
        });

        if (failureResult != null)
        {
            await errors.Writer.WriteAsync(failureResult);
            return;
        }

        // If we have the files from both locations present in the hash, validate if the hashes match.
        if (newValue?.FileLocation == Sbom.Entities.FileLocation.All)
        {
            // A missing hash on either side means there is nothing to compare, so it cannot count as a match.
            if (!string.IsNullOrEmpty(newValue.OnDiskHash?.ChecksumValue) &&
                string.Equals(newValue.OnDiskHash?.ChecksumValue, newValue.SbomFileHash?.ChecksumValue, StringComparison.InvariantCultureIgnoreCase))
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
