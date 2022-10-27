using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Common.Config;
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
        private readonly ChannelUtils channelUtils;
        private readonly ILogger log;
        private readonly FileHasher fileHasher;
        private readonly ManifestFolderFilterer fileFilterer;
        private readonly HashValidator2 hashValidator;
        private readonly EnumeratorChannel enumeratorChannel;
        private readonly SBOMFileToFileInfoConverter fileConverter;

        public FilesValidator(DirectoryWalker directoryWalker, IConfiguration configuration, ChannelUtils channelUtils, ILogger log, FileHasher fileHasher, ManifestFolderFilterer fileFilterer, HashValidator2 hashValidator, EnumeratorChannel enumeratorChannel, SBOMFileToFileInfoConverter fileConverter)
        {
            this.directoryWalker = directoryWalker;
            this.configuration = configuration;
            this.channelUtils = channelUtils;
            this.log = log;
            this.fileHasher = fileHasher;
            this.fileFilterer = fileFilterer;
            this.hashValidator = hashValidator;
            this.enumeratorChannel = enumeratorChannel;
            this.fileConverter = fileConverter;
        }

        public async Task<(List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>)> Validate(ISbomParser sbomParser)
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var results = new List<ChannelReader<FileValidationResult>>();

            var (onDiskFileResults, onDiskFileErrors) = GetOnDiskFiles();
            results.AddRange(onDiskFileResults);
            errors.AddRange(onDiskFileErrors);

            var (inSbomFileResults, inSbomFileErrors) = GetOnDiskFiles();
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
                Console.WriteLine($"Error {error}");
            }

            return (results, errors);
        }

        private (List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>) GetOnDiskFiles()
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var filesWithHashes = new List<ChannelReader<FileValidationResult>>();

            // Read all files
            var (files, dirErrors) = directoryWalker.GetFilesRecursively(configuration.BuildDropPath.Value);
            errors.Add(dirErrors);

            // Filter root path matching files from the manifest map.
            //var manifestFilterErrors = manifestFileFilterer.FilterManifestFiles();
            //errors.Add(manifestFilterErrors);

            log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
            var splitFilesChannels = channelUtils.Split(files, configuration.Parallelism.Value);

            log.Debug("Waiting for the workflow to finish...");
            foreach (var fileChannel in splitFilesChannels)
            {
                // Filter files
                var (filteredFiles, filteringErrors) = fileFilterer.FilterFiles(fileChannel);
                errors.Add(filteringErrors);

                // Generate hash code for each file.
                var (fileHashes, hashingErrors) = fileHasher.Run(filteredFiles, Sbom.Entities.FileLocation.OnDisk);
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
                var (internalSbomFiles, converterErrors) = fileConverter.Convert(fileChannel, Sbom.Entities.FileLocation.InSbomFile);
                errors.Add(converterErrors);

                var (validationResults, validationErrors) = hashValidator.Validate(internalSbomFiles);
                errors.Add(validationErrors);

                filesWithHashes.Add(validationResults);
            }

            return (filesWithHashes, errors);
        }

    }
}
