// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;

namespace Microsoft.Sbom.Api.Workflows;

using Microsoft.Extensions.Logging;

/// <summary>
/// Defines the workflow steps for the drop validation action.
/// </summary>
public class SbomValidationWorkflow : IWorkflow<SbomValidationWorkflow>
{
    private readonly IConfiguration configuration;
    private readonly DirectoryWalker directoryWalker;
    private readonly ChannelUtils channelUtils;
    private readonly FileHasher fileHasher;
    private readonly HashValidator hashValidator;
    private readonly ManifestData manifestData;
    private readonly ManifestFolderFilterer fileFilterer;
    private readonly ValidationResultGenerator validationResultGenerator;
    private readonly IOutputWriter outputWriter;
    private readonly ILogger<SbomValidationWorkflow> log;
    private readonly ISignValidationProvider signValidationProvider;
    private readonly ManifestFileFilterer manifestFileFilterer;
    private readonly IRecorder recorder;

    public SbomValidationWorkflow(
        IConfiguration configuration,
        DirectoryWalker directoryWalker,
        ManifestFolderFilterer fileFilterer,
        ChannelUtils channelUtils,
        FileHasher fileHasher,
        HashValidator hashValidator,
        ManifestData manifestData,
        ValidationResultGenerator validationResultGenerator,
        IOutputWriter outputWriter,
        ILogger<SbomValidationWorkflow> log,
        ISignValidationProvider signValidationProvider,
        ManifestFileFilterer manifestFileFilterer,
        IRecorder recorder)
    {
        this.configuration = configuration;
        this.directoryWalker = directoryWalker;
        this.channelUtils = channelUtils;
        this.hashValidator = hashValidator;
        this.manifestData = manifestData;
        this.log = log;
        this.fileFilterer = fileFilterer;
        this.signValidationProvider = signValidationProvider;
        this.validationResultGenerator = validationResultGenerator;
        this.outputWriter = outputWriter;
        this.manifestFileFilterer = manifestFileFilterer;
        this.recorder = recorder;
        this.fileHasher = fileHasher;
        if (this.fileHasher != null)
        {
            this.fileHasher.ManifestData = manifestData;
        }
    }

    public async Task<bool> RunAsync()
    {
        ValidationResult validationResultOutput = null;
        IEnumerable<FileValidationResult> validFailures = null;
        using (recorder.TraceEvent(Events.SBOMValidationWorkflow))
        {
            try
            {
                log.LogDebug("Starting validation workflow.");
                DateTime start = DateTime.Now;

                IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();
                IList<ChannelReader<FileValidationResult>> results = new List<ChannelReader<FileValidationResult>>();

                // Validate signature
                if (configuration.ValidateSignature != null && configuration.ValidateSignature.Value)
                {
                    var signValidator = signValidationProvider.Get();

                    if (signValidator == null)
                    {
                        log.LogWarning($"ValidateSignature switch is true, but couldn't find a sign validator for the current OS, skipping validation.");
                    }
                    else
                    {
                        if (!signValidator.Validate())
                        {
                            log.LogError("Sign validation failed.");
                            return false;
                        }
                    }
                }

                // Workflow
                // Read all files
                var (files, dirErrors) = directoryWalker.GetFilesRecursively(configuration.BuildDropPath.Value);
                errors.Add(dirErrors);

                // Filter root path matching files from the manifest map.
                var manifestFilterErrors = manifestFileFilterer.FilterManifestFiles();
                errors.Add(manifestFilterErrors);

                log.LogDebug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
                var splitFilesChannels = channelUtils.Split(files, configuration.Parallelism.Value);

                log.LogDebug("Waiting for the workflow to finish...");
                foreach (var fileChannel in splitFilesChannels)
                {
                    // Filter files
                    var (filteredFiles, filteringErrors) = fileFilterer.FilterFiles(fileChannel);
                    errors.Add(filteringErrors);

                    // Generate hash code for each file.
                    var (fileHashes, hashingErrors) = fileHasher.Run(filteredFiles);
                    errors.Add(hashingErrors);

                    // Validate hashes for each file.
                    var (validationResults, validationErrors) = hashValidator.Validate(fileHashes);
                    errors.Add(validationErrors);
                    results.Add(validationResults);
                }

                // 4. Wait for the pipeline to finish.
                int successCount = 0;
                var failures = new List<FileValidationResult>();

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

                // 5. Collect remaining entries in ManifestMap
                failures.AddRange(
                    from manifestItem in manifestData.HashesMap
                    select new FileValidationResult
                    {
                        ErrorType = ErrorType.MissingFile,
                        Path = manifestItem.Key
                    });

                // Failure
                if (successCount < 0)
                {
                    log.LogError("Error running the workflow, failing without publishing results.");
                    return false;
                }

                DateTime end = DateTime.Now;
                log.LogDebug("Finished workflow, gathering results.");

                // 6. Generate JSON output
                validationResultOutput = validationResultGenerator
                    .WithTotalFilesInManifest(manifestData.Count)
                    .WithSuccessCount(successCount)
                    .WithTotalDuration(end - start)
                    .WithValidationResults(failures)
                    .Build();

                // 7. Write JSON output to file.
                var options = new JsonSerializerOptions
                {
                    Converters =
                    {
                        new JsonStringEnumConverter()
                    }
                };
                await outputWriter.WriteAsync(JsonSerializer.Serialize(validationResultOutput, options));
                validFailures = failures.Where(a => a.ErrorType != ErrorType.ManifestFolder
                                                    && a.ErrorType != ErrorType.FilteredRootPath);

                if (configuration.IgnoreMissing.Value)
                {
                    log.LogWarning("Not including missing files on disk as -IgnoreMissing switch is on.");
                    validFailures = validFailures.Where(a => a.ErrorType != ErrorType.MissingFile);
                }

                return !validFailures.Any();
            }
            catch (Exception e)
            {
                recorder.RecordException(e);
                log.LogError("Encountered an error while validating the drop.");
                log.LogError($"Error details: {e.Message}");
                return false;
            }
            finally
            {
                if (validFailures != null)
                {
                    recorder.RecordTotalErrors(validFailures.ToList());
                }

                // Log telemetry
                LogResultsSummary(validationResultOutput, validFailures);
                LogIndividualFileResults(validFailures);
            }
        }
    }

    private void LogIndividualFileResults(IEnumerable<FileValidationResult> validFailures)
    {
        if (validFailures == null)
        {
            // We failed to generate the output due to a workflow error.
            return;
        }

        log.LogTrace(string.Empty);
        log.LogTrace("------------------------------------------------------------");
        log.LogTrace("Individual file validation results");
        log.LogTrace("------------------------------------------------------------");
        log.LogTrace(string.Empty);

        log.LogTrace("Additional files not in the manifest: ");
        log.LogTrace(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.AdditionalFile).ForEach(f => log.LogTrace(f.Path));
        log.LogTrace("------------------------------------------------------------");

        log.LogTrace("Files with invalid hashes:");
        log.LogTrace(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.InvalidHash).ForEach(f => log.LogTrace(f.Path));
        log.LogTrace("------------------------------------------------------------");

        log.LogTrace("Files in the manifest missing from the disk:");
        log.LogTrace(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.MissingFile).ForEach(f => log.LogTrace(f.Path));
        log.LogTrace("------------------------------------------------------------");

        log.LogTrace("Unknown file failures:");
        log.LogTrace(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.Other).ForEach(f => log.LogTrace(f.Path));
        log.LogTrace("------------------------------------------------------------");
    }

    private void LogResultsSummary(ValidationResult validationResultOutput, IEnumerable<FileValidationResult> validFailures)
    {
        if (validationResultOutput == null || validFailures == null)
        {
            // We failed to generate the output due to a workflow error.
            return;
        }

        log.LogDebug(string.Empty);
        log.LogDebug("------------------------------------------------------------");
        log.LogDebug("Validation Summary");
        log.LogDebug("------------------------------------------------------------");
        log.LogDebug(string.Empty);

        log.LogDebug($"Validation Result . . . . . . . . . . . . . . . .{validationResultOutput.Result}");
        log.LogDebug($"Total execution time (sec) . . . . . . . . . . . {validationResultOutput.Summary.TotalExecutionTimeInSeconds}");
        log.LogDebug($"Files failed . . . . . . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount}");
        log.LogDebug($"Files successfully validated . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount}");
        log.LogDebug($"Total files validated. . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesValidatedCount}");
        log.LogDebug($"Total files in manifest. . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest}");
        log.LogDebug($"");
        log.LogDebug($"Additional files not in the manifest . . . . . . {validFailures.Count(v => v.ErrorType == ErrorType.AdditionalFile)}");
        log.LogDebug($"Files with invalid hashes . . . . . . . . . . . .{validFailures.Count(v => v.ErrorType == ErrorType.InvalidHash)}");
        log.LogDebug($"Files in the manifest missing from the disk . . .{validFailures.Count(v => v.ErrorType == ErrorType.MissingFile)}");
        log.LogDebug($"Unknown file failures . . . . . . . . . . . . .  {validFailures.Count(v => v.ErrorType == ErrorType.Other)}");
    }
}
