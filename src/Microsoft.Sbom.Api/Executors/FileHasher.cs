﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Serilog;
using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Given a list of file paths, returns a <see cref="FileInfo"/> object containing the
    /// file's path in the manifest file format and its hash code.
    /// </summary>
    public class FileHasher
    {
        private readonly IHashCodeGenerator hashCodeGenerator;
        private readonly IManifestPathConverter manifestPathConverter;
        private readonly ILogger log;
        private readonly ISbomConfigProvider sbomConfigs;
        private readonly IFileTypeUtils fileTypeUtils;
        private readonly AlgorithmName[] hashAlgorithmNames;

        public ManifestData ManifestData { get; set; }

        public FileHasher(
            IHashCodeGenerator hashCodeGenerator,
            IManifestPathConverter manifestPathConverter,
            ILogger log,
            IConfiguration configuration,
            ISbomConfigProvider sbomConfigs,
            ManifestGeneratorProvider manifestGeneratorProvider,
            FileTypeUtils fileTypeUtils)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (manifestGeneratorProvider is null)
            {
                throw new ArgumentNullException(nameof(manifestGeneratorProvider));
            }

            this.hashCodeGenerator = hashCodeGenerator ?? throw new ArgumentNullException(nameof(hashCodeGenerator));
            this.manifestPathConverter = manifestPathConverter ?? throw new ArgumentNullException(nameof(manifestPathConverter));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
            this.fileTypeUtils = fileTypeUtils ?? throw new ArgumentNullException(nameof(fileTypeUtils));

            // Set the hash algorithms to calculate based on the action.
            switch (configuration.ManifestToolAction)
            {
                case ManifestToolActions.Validate:
                    hashAlgorithmNames = new AlgorithmName[]
                    {
                        configuration.HashAlgorithm.Value
                    };
                    break;
                case ManifestToolActions.Generate:

                    hashAlgorithmNames = sbomConfigs.GetManifestInfos()
                                            .Select(config => manifestGeneratorProvider
                                                                .Get(config)
                                                                .RequiredHashAlgorithms)
                                            .SelectMany(h => h)
                                            .Distinct()
                                            .ToArray();
                    break;
            }
        }

        public (ChannelReader<InternalSBOMFileInfo>, ChannelReader<FileValidationResult>) Run(ChannelReader<string> fileInfo)
        {
            var output = Channel.CreateUnbounded<InternalSBOMFileInfo>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                await foreach (string file in fileInfo.ReadAllAsync())
                {
                    await GenerateHash(file, output, errors);
                }

                output.Writer.Complete();
                errors.Writer.Complete();
            });

            return (output, errors);
        }

        private async Task GenerateHash(string file, Channel<InternalSBOMFileInfo> output, Channel<FileValidationResult> errors)
        {
            string relativeFilePath = null;
            bool isOutsideDropPath = false;
            try
            {
                (relativeFilePath, isOutsideDropPath) = manifestPathConverter.Convert(file);
                Checksum[] fileHashes = hashCodeGenerator.GenerateHashes(file, hashAlgorithmNames);
                if (fileHashes == null || fileHashes.Length == 0 || fileHashes.Any(f => string.IsNullOrEmpty(f.ChecksumValue)))
                {
                    throw new HashGenerationException($"Failed to generate hashes for '{file}'.");
                }

                // Record hashes
                sbomConfigs.ApplyToEachConfig(config => config.Recorder.RecordChecksumForFile(fileHashes));

                await output.Writer.WriteAsync(
                    new InternalSBOMFileInfo
                    {
                        Path = relativeFilePath,
                        IsOutsideDropPath = isOutsideDropPath,
                        Checksum = fileHashes,
                        FileTypes = fileTypeUtils.GetFileTypesBy(file),
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
}
