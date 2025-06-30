// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using IConfiguration = Microsoft.Sbom.Common.Config.IConfiguration;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Given a list of file paths, returns a <see cref="FileInfo"/> object containing the
/// file's path in the manifest file format and its hash code.
/// </summary>
public class FileHasher
{
    private readonly IHashCodeGenerator hashCodeGenerator;
    private readonly IManifestPathConverter manifestPathConverter;
    private readonly ILogger log;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly IFileTypeUtils fileTypeUtils;
    private AlgorithmName[] hashAlgorithmNames;

    private AlgorithmName[] HashAlgorithmNames
    {
        get
        {
            // Set the hash algorithms to calculate based on the action.
            hashAlgorithmNames ??= configuration.ManifestToolAction switch
            {
                ManifestToolActions.Validate => new AlgorithmName[]
                {
                    configuration.HashAlgorithm.Value
                },
                ManifestToolActions.Consolidate => new AlgorithmName[]
                {
                    configuration.HashAlgorithm.Value
                },
                ManifestToolActions.Generate => sbomConfigs.GetManifestInfos()
                    .Select(config => manifestGeneratorProvider
                        .Get(config)
                        .RequiredHashAlgorithms)
                    .SelectMany(h => h)
                    .Distinct()
                    .ToArray(),
                _ => null
            };

            return hashAlgorithmNames;
        }
    }

    public ManifestData ManifestData { get; set; }

    public FileHasher(
        IHashCodeGenerator hashCodeGenerator,
        IManifestPathConverter manifestPathConverter,
        ILogger log,
        IConfiguration configuration,
        ISbomConfigProvider sbomConfigs,
        ManifestGeneratorProvider manifestGeneratorProvider,
        IFileTypeUtils fileTypeUtils)
    {
        this.hashCodeGenerator = hashCodeGenerator ?? throw new ArgumentNullException(nameof(hashCodeGenerator));
        this.manifestPathConverter = manifestPathConverter ?? throw new ArgumentNullException(nameof(manifestPathConverter));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.manifestGeneratorProvider = manifestGeneratorProvider ?? throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        this.fileTypeUtils = fileTypeUtils ?? throw new ArgumentNullException(nameof(fileTypeUtils));
    }

    public (ChannelReader<InternalSbomFileInfo>, ChannelReader<FileValidationResult>) Run(ChannelReader<string> fileInfo, FileLocation fileLocation = FileLocation.OnDisk, bool prependDotToPath = false)
    {
        var output = Channel.CreateUnbounded<InternalSbomFileInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        Task.Run(async () =>
        {
            await foreach (var file in fileInfo.ReadAllAsync())
            {
                await GenerateHash(file, output, errors, fileLocation, prependDotToPath);
            }

            output.Writer.Complete();
            errors.Writer.Complete();
        });

        return (output, errors);
    }

    private async Task GenerateHash(string file, Channel<InternalSbomFileInfo> output, Channel<FileValidationResult> errors, FileLocation fileLocation, bool prependDotToPath = false)
    {
        string relativeFilePath = null;
        var isOutsideDropPath = false;
        try
        {
            (relativeFilePath, isOutsideDropPath) = manifestPathConverter.Convert(file, prependDotToPath);
            var fileHashes = hashCodeGenerator.GenerateHashes(file, HashAlgorithmNames);
            if (fileHashes == null || fileHashes.Length == 0 || fileHashes.Any(f => string.IsNullOrEmpty(f.ChecksumValue)))
            {
                throw new HashGenerationException($"Failed to generate hashes for '{file}'.");
            }

            // Record hashes
            sbomConfigs.ApplyToEachConfig(config => config.Recorder.RecordChecksumForFile(fileHashes));

            await output.Writer.WriteAsync(
                new InternalSbomFileInfo
                {
                    Path = relativeFilePath,
                    IsOutsideDropPath = isOutsideDropPath,
                    Checksum = fileHashes,
                    FileTypes = fileTypeUtils.GetFileTypesBy(file),
                    FileLocation = fileLocation
                });
        }
        catch (Exception e)
        {
            if (ManifestData != null && !string.IsNullOrWhiteSpace(relativeFilePath))
            {
                ManifestData.HashesMap.Remove(relativeFilePath);
            }

            log.Error($"Encountered an error while generating hash for file {file}: {e.Message}");
            await errors.Writer.WriteAsync(new FileValidationResult
            {
                ErrorType = Entities.ErrorType.Other,
                Path = relativeFilePath ?? file
            });
        }
    }
}
