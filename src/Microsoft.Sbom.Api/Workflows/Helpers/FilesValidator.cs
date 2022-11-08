// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Entities;
using Ninject;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    public class FilesValidator
    {
        private readonly DirectoryWalker directoryWalker;
        private readonly IConfiguration configuration;
        private readonly ChannelUtils channelUtils = new ();
        private readonly ILogger log;
        private readonly FileHasher fileHasher;
        private readonly ManifestFolderFilterer fileFilterer;
        private readonly HashValidator2 hashValidator;
        private readonly EnumeratorChannel enumeratorChannel;
        private readonly SBOMFileToFileInfoConverter fileConverter;
        private readonly FileHashesDictionary fileHashesDictionary;
        private readonly FileFilterer spdxFileFilterer;

        public FilesValidator(
            DirectoryWalker directoryWalker,
            IConfiguration configuration,
            ILogger log,
            FileHasher fileHasher,
            ManifestFolderFilterer fileFilterer,
            HashValidator2 hashValidator,
            EnumeratorChannel enumeratorChannel,
            SBOMFileToFileInfoConverter fileConverter,
            FileHashesDictionary fileHashesDictionary,
            FileFilterer spdxFileFilterer)
        {
            this.directoryWalker = directoryWalker ?? throw new ArgumentNullException(nameof(directoryWalker));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.fileHasher = fileHasher ?? throw new ArgumentNullException(nameof(fileHasher));
            this.fileFilterer = fileFilterer ?? throw new ArgumentNullException(nameof(fileFilterer));
            this.hashValidator = hashValidator ?? throw new ArgumentNullException(nameof(hashValidator));
            this.enumeratorChannel = enumeratorChannel ?? throw new ArgumentNullException(nameof(enumeratorChannel));
            this.fileConverter = fileConverter ?? throw new ArgumentNullException(nameof(fileConverter));
            this.fileHashesDictionary = fileHashesDictionary ?? throw new ArgumentNullException(nameof(fileHashesDictionary));
            this.spdxFileFilterer = spdxFileFilterer ?? throw new ArgumentNullException(nameof(spdxFileFilterer));
        }

        public async Task<(int, List<FileValidationResult>)> Validate(ISbomParser sbomParser)
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var results = new List<ChannelReader<FileValidationResult>>();
            var failures = new List<FileValidationResult>();

            var (onDiskFileResults, onDiskFileErrors) = GetOnDiskFiles();
            results.AddRange(onDiskFileResults);
            errors.AddRange(onDiskFileErrors);

            var (inSbomFileResults, inSbomFileErrors) = GetInsideSbomFiles(sbomParser);
            results.AddRange(inSbomFileResults);
            errors.AddRange(inSbomFileErrors);

            int successCount = 0;
            ChannelReader<FileValidationResult> resultChannel = channelUtils.Merge(results.ToArray());
            await foreach (FileValidationResult validationResult in resultChannel.ReadAllAsync())
            {
                successCount++;
            }

            ChannelReader<FileValidationResult> workflowErrors = channelUtils.Merge(errors.ToArray());

            await foreach (FileValidationResult error in workflowErrors.ReadAllAsync())
            {
                failures.Add(error);
            }

            foreach (var file in fileHashesDictionary.FileHashes)
            {
                switch (file.Value.FileLocation)
                {
                    case FileLocation.OnDisk:
                        failures.Add(new FileValidationResult
                        {
                            ErrorType = ErrorType.AdditionalFile,
                            Path = file.Key,
                        });
                        break;
                    case FileLocation.InSbomFile:
                        failures.Add(new FileValidationResult
                        {
                            ErrorType = ErrorType.MissingFile,
                            Path = file.Key,
                        });
                        break;
                }
            }

            return (successCount, failures);
        }

        private (List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>) GetOnDiskFiles()
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var filesWithHashes = new List<ChannelReader<FileValidationResult>>();

            // Read all files
            var (files, dirErrors) = directoryWalker.GetFilesRecursively(configuration.BuildDropPath.Value);
            errors.Add(dirErrors);

            log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
            var splitFilesChannels = channelUtils.Split(files, configuration.Parallelism.Value);

            log.Debug("Waiting for the workflow to finish...");
            foreach (var fileChannel in splitFilesChannels)
            {
                // Filter files
                var (filteredFiles, filteringErrors) = fileFilterer.FilterFiles(fileChannel);
                errors.Add(filteringErrors);

                // Generate hash code for each file.
                var (fileHashes, hashingErrors) = fileHasher.Run(filteredFiles, FileLocation.OnDisk, true);
                errors.Add(hashingErrors);

                var (validationResults, validationErrors) = hashValidator.Validate(fileHashes);
                errors.Add(validationErrors);

                filesWithHashes.Add(validationResults);
            }

            return (filesWithHashes, errors);
        }

        private (List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>) GetInsideSbomFiles(ISbomParser sbomParser)
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var filesWithHashes = new List<ChannelReader<FileValidationResult>>();

            var (sbomFiles, sbomFileErrors) = enumeratorChannel.Enumerate(sbomParser.GetFiles);
            errors.Add(sbomFileErrors);

            log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
            var splitFilesChannels = channelUtils.Split(sbomFiles, configuration.Parallelism.Value);

            log.Debug("Waiting for the workflow to finish...");
            foreach (var fileChannel in splitFilesChannels)
            {
                var (internalSbomFiles, converterErrors) = fileConverter.Convert(fileChannel, FileLocation.InSbomFile);
                errors.Add(converterErrors);

                var (filteredSbomFiles, filterErrors) = spdxFileFilterer.FilterSPDXFiles(internalSbomFiles);
                errors.Add(filterErrors);

                var (validationResults, validationErrors) = hashValidator.Validate(filteredSbomFiles);
                errors.Add(validationErrors);

                filesWithHashes.Add(validationResults);
            }

            return (filesWithHashes, errors);
        }

    }
}
