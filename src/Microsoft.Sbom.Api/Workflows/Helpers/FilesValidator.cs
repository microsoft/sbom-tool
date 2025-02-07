// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;
using Microsoft.Sbom.Utils;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Validates over files present in the SBOM file and on disk.
/// </summary>
public class FilesValidator
{
    private readonly DirectoryWalker directoryWalker;
    private readonly IConfiguration configuration;
    private readonly ChannelUtils channelUtils = new();
    private readonly ILogger log;
    private readonly FileHasher fileHasher;
    private readonly ManifestFolderFilterer fileFilterer;
    private readonly ConcurrentSha256HashValidator hashValidator;
    private readonly EnumeratorChannel enumeratorChannel;
    private readonly SbomFileToFileInfoConverter fileConverter;
    private readonly FileHashesDictionary fileHashesDictionary;
    private readonly FileFilterer spdxFileFilterer;

    public FilesValidator(
        DirectoryWalker directoryWalker,
        IConfiguration configuration,
        ILogger log,
        FileHasher fileHasher,
        ManifestFolderFilterer fileFilterer,
        ConcurrentSha256HashValidator hashValidator,
        EnumeratorChannel enumeratorChannel,
        SbomFileToFileInfoConverter fileConverter,
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

    public async Task<(int, List<FileValidationResult>)> Validate(IEnumerable<SPDXFile> files)
    {
        var errors = new List<ChannelReader<FileValidationResult>>();
        var results = new List<ChannelReader<FileValidationResult>>();
        var failures = new Dictionary<string, FileValidationResult>();

        var (onDiskFileResults, onDiskFileErrors) = GetOnDiskFiles();
        results.AddRange(onDiskFileResults);
        errors.AddRange(onDiskFileErrors);

        var (inSbomFileResults, inSbomFileErrors) = GetInsideSbomFiles(files);
        results.AddRange(inSbomFileResults);
        errors.AddRange(inSbomFileErrors);

        var successCount = 0;
        var resultChannel = channelUtils.Merge(results.ToArray());
        await foreach (var validationResult in resultChannel.ReadAllAsync())
        {
            successCount++;
        }

        var workflowErrors = channelUtils.Merge(errors.ToArray());

        await foreach (var error in workflowErrors.ReadAllAsync())
        {
            failures.Add(error.Path, error);
        }

        foreach (var file in fileHashesDictionary.FileHashes)
        {
            if (failures.ContainsKey(file.Key))
            {
                // If we have added a validation error for this file, we don't need to add another one.
                continue;
            }

            if (file.Value == null)
            {
                // This generally means that we have case variations in the file names.
                failures.Add(file.Key, new FileValidationResult
                {
                    ErrorType = ErrorType.AdditionalFile,
                    Path = file.Key,
                });
                continue;
            }

            switch (file.Value.FileLocation)
            {
                case FileLocation.OnDisk:
                    failures.Add(file.Key, new FileValidationResult
                    {
                        ErrorType = ErrorType.AdditionalFile,
                        Path = file.Key,
                    });
                    break;
                case FileLocation.InSbomFile:
                    failures.Add(file.Key, new FileValidationResult
                    {
                        ErrorType = ErrorType.MissingFile,
                        Path = file.Key,
                    });
                    break;
            }
        }

        return (successCount, failures.Values.ToList());
    }

    public async Task<(int, List<FileValidationResult>)> Validate(IEnumerable<File> files)
    {
        var errors = new List<ChannelReader<FileValidationResult>>();
        var results = new List<ChannelReader<FileValidationResult>>();
        var failures = new Dictionary<string, FileValidationResult>();

        var (onDiskFileResults, onDiskFileErrors) = GetOnDiskFiles();
        results.AddRange(onDiskFileResults);
        errors.AddRange(onDiskFileErrors);

        var workflowErrors = channelUtils.Merge(errors.ToArray());
        await foreach (var error in workflowErrors.ReadAllAsync())
        {
            failures.Add(error.Path, error);
        }

        var (inSbomFileResults, inSbomFileErrors) = GetInsideSbomFiles(files);
        results.AddRange(inSbomFileResults);
        errors.AddRange(inSbomFileErrors);

        var successCount = 0;
        var resultChannel = channelUtils.Merge(results.ToArray());
        await foreach (var validationResult in resultChannel.ReadAllAsync())
        {
            successCount++;
        }

        workflowErrors = channelUtils.Merge(errors.ToArray());

        await foreach (var error in workflowErrors.ReadAllAsync())
        {
            failures.Add(error.Path, error);
        }

        foreach (var file in fileHashesDictionary.FileHashes)
        {
            if (failures.ContainsKey(file.Key))
            {
                // If we have added a validation error for this file, we don't need to add another one.
                continue;
            }

            if (file.Value == null)
            {
                // This generally means that we have case variations in the file names.
                failures.Add(file.Key, new FileValidationResult
                {
                    ErrorType = ErrorType.AdditionalFile,
                    Path = file.Key,
                });
                continue;
            }

            switch (file.Value.FileLocation)
            {
                case FileLocation.OnDisk:
                    failures.Add(file.Key, new FileValidationResult
                    {
                        ErrorType = ErrorType.AdditionalFile,
                        Path = file.Key,
                    });
                    break;
                case FileLocation.InSbomFile:
                    failures.Add(file.Key, new FileValidationResult
                    {
                        ErrorType = ErrorType.MissingFile,
                        Path = file.Key,
                    });
                    break;
            }
        }

        return (successCount, failures.Values.ToList());
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

    private (List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>) GetInsideSbomFiles(IEnumerable<SPDXFile> files)
    {
        var errors = new List<ChannelReader<FileValidationResult>>();
        var filesWithHashes = new List<ChannelReader<FileValidationResult>>();

        // Enumerate files from SBOM
        var (sbomFiles, sbomFileErrors) = enumeratorChannel.Enumerate(() => files.Select(f => f.ToSbomFile()));
        errors.Add(sbomFileErrors);

        log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
        var splitFilesChannels = channelUtils.Split(sbomFiles, configuration.Parallelism.Value);

        log.Debug("Waiting for the workflow to finish...");
        foreach (var fileChannel in splitFilesChannels)
        {
            // Convert files to internal SBOM format.
            var (internalSbomFiles, converterErrors) = fileConverter.Convert(fileChannel, FileLocation.InSbomFile);
            errors.Add(converterErrors);

            // Filter files.
            var (filteredSbomFiles, filterErrors) = spdxFileFilterer.Filter(internalSbomFiles);
            errors.Add(filterErrors);

            var (validationResults, validationErrors) = hashValidator.Validate(filteredSbomFiles);
            errors.Add(validationErrors);

            filesWithHashes.Add(validationResults);
        }

        return (filesWithHashes, errors);
    }

    private (List<ChannelReader<FileValidationResult>>, List<ChannelReader<FileValidationResult>>) GetInsideSbomFiles(IEnumerable<File> files)
    {
        var errors = new List<ChannelReader<FileValidationResult>>();
        var filesWithHashes = new List<ChannelReader<FileValidationResult>>();

        // Enumerate files from SBOM

        var file = files.FirstOrDefault().ToSbomFile();
        Console.WriteLine(file.Path);

        var (sbomFiles, sbomFileErrors) = enumeratorChannel.Enumerate(() => files.Select(f => f.ToSbomFile()));
        errors.Add(sbomFileErrors);

        log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
        var splitFilesChannels = channelUtils.Split(sbomFiles, configuration.Parallelism.Value);

        log.Debug("Waiting for the workflow to finish...");
        foreach (var fileChannel in splitFilesChannels)
        {
            // Convert files to internal SBOM format.
            var (internalSbomFiles, converterErrors) = fileConverter.Convert(fileChannel, FileLocation.InSbomFile);
            errors.Add(converterErrors);

            // Filter files.
            var (filteredSbomFiles, filterErrors) = spdxFileFilterer.Filter(internalSbomFiles);
            //errors.Add(filterErrors);

            var (validationResults, validationErrors) = hashValidator.Validate(filteredSbomFiles);
            //errors.Add(validationErrors);

            filesWithHashes.Add(validationResults);
        }

        return (filesWithHashes, errors);
    }
}
