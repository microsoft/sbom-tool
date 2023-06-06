// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using PowerArgs;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Workflows;

/// <summary>
/// Validates a SBOM against a given drop path. Uses the <see cref="ISbomParser"/> to read
/// objects inside a SBOM.
/// </summary>
public class SbomParserBasedValidationWorkflow : IWorkflow<SbomParserBasedValidationWorkflow>
{
    private readonly IRecorder recorder;
    private readonly ISignValidationProvider signValidationProvider;
    private readonly ILogger log;
    private readonly IManifestParserProvider manifestParserProvider;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly FilesValidator filesValidator;
    private readonly ValidationResultGenerator validationResultGenerator;
    private readonly IOutputWriter outputWriter;
    private readonly IFileSystemUtils fileSystemUtils;

    public SbomParserBasedValidationWorkflow(IRecorder recorder, ISignValidationProvider signValidationProvider, ILogger log, IManifestParserProvider manifestParserProvider, IConfiguration configuration, ISbomConfigProvider sbomConfigs, FilesValidator filesValidator, ValidationResultGenerator validationResultGenerator, IOutputWriter outputWriter, IFileSystemUtils fileSystemUtils)
    {
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.signValidationProvider = signValidationProvider ?? throw new ArgumentNullException(nameof(signValidationProvider));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.manifestParserProvider = manifestParserProvider ?? throw new ArgumentNullException(nameof(manifestParserProvider));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.filesValidator = filesValidator ?? throw new ArgumentNullException(nameof(filesValidator));
        this.validationResultGenerator = validationResultGenerator ?? throw new ArgumentNullException(nameof(validationResultGenerator));
        this.outputWriter = outputWriter ?? throw new ArgumentNullException(nameof(outputWriter));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public async Task<bool> RunAsync()
    {
        ValidationResult validationResultOutput = null;
        IEnumerable<FileValidationResult> validFailures = null;
        IEnumerable<FileValidationResult> optionalValidFailures = null;
        int totalNumberOfPackages = 0;

        using (recorder.TraceEvent(Events.SBOMValidationWorkflow))
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo.Value.FirstOrDefault());

                using Stream stream = fileSystemUtils.OpenRead(sbomConfig.ManifestJsonFilePath);
                var manifestInterface = manifestParserProvider.Get(sbomConfig.ManifestInfo);
                var sbomParser = manifestInterface.CreateParser(stream);

                // Validate signature
                if (configuration.ValidateSignature != null && configuration.ValidateSignature.Value)
                {
                    var signValidator = signValidationProvider.Get();

                    if (signValidator == null)
                    {
                        log.Warning($"ValidateSignature switch is true, but couldn't find a sign validator for the current OS, skipping validation.");
                    }
                    else
                    {
                        if (!signValidator.Validate())
                        {
                            log.Error("Sign validation failed.");
                            return false;
                        }
                    }
                }

                int successfullyValidatedFiles = 0;
                List<FileValidationResult> fileValidationFailures = null;
                List<FileValidationResult> optionalFailures = null;

                while (sbomParser.Next() != Contracts.Enums.ParserState.FINISHED)
                {
                    switch (sbomParser.CurrentState)
                    {
                        case Contracts.Enums.ParserState.FILES:
                            (successfullyValidatedFiles, fileValidationFailures) = await filesValidator.Validate(sbomParser);
                            break;
                        case Contracts.Enums.ParserState.PACKAGES:
                            var packages = sbomParser.GetPackages().ToList();
                            totalNumberOfPackages = packages.Count();
                            break;
                        case Contracts.Enums.ParserState.RELATIONSHIPS:
                            sbomParser.GetRelationships().ToList();
                            break;
                        case Contracts.Enums.ParserState.REFERENCES:
                            sbomParser.GetReferences().ToList();
                            break;
                        case Contracts.Enums.ParserState.NONE:
                            break;
                        case Contracts.Enums.ParserState.METADATA:
                            break;
                        case Contracts.Enums.ParserState.INTERNAL_SKIP:
                            break;
                        case Contracts.Enums.ParserState.FINISHED:
                            break;
                        default: break;
                    }
                }

                if (configuration.FailIfNoPackages?.Value == true && totalNumberOfPackages <= 1)
                {
                    optionalFailures = new List<FileValidationResult>
                    {
                        new FileValidationResult
                        {
                            ErrorType = ErrorType.NoPackagesFound
                        }
                    };
                }

                log.Debug("Finished workflow, gathering results.");

                // Generate JSON output
                validationResultOutput = validationResultGenerator
                    .WithTotalFilesInManifest(sbomConfig.Recorder.GetGenerationData().Checksums.Count())
                    .WithTotalPackagesInManifest(totalNumberOfPackages)
                    .WithSuccessCount(successfullyValidatedFiles)
                    .WithTotalDuration(sw.Elapsed)
                    .WithValidationResults(fileValidationFailures)
                    .WithOptionalValidationResults(optionalFailures)
                    .Build();

                // Write JSON output to file.
                var options = new JsonSerializerOptions
                {
                    Converters =
                    {
                        new JsonStringEnumConverter()
                    }
                };

                await outputWriter.WriteAsync(JsonSerializer.Serialize(validationResultOutput, options));
                    
                validFailures = fileValidationFailures.Where(f => !Constants.SkipFailureReportingForErrors.Contains(f.ErrorType));
                optionalValidFailures = optionalFailures?.Where(f => !Constants.SkipFailureReportingForErrors.Contains(f.ErrorType));

                if (configuration.IgnoreMissing.Value)
                {
                    log.Warning("Not including missing files on disk as -IgnoreMissing switch is on.");
                    validFailures = validFailures.Where(a => a.ErrorType != ErrorType.MissingFile);
                }

                // Add optional validation failures to the list of failures if the flag was set to true.
                if (configuration.FailIfNoPackages?.Value == true)
                {
                    validFailures = validFailures.Concat(optionalValidFailures);
                }          

                return !validFailures.Any();
            }
            catch (Exception e)
            {
                recorder.RecordException(e);
                log.Error("Encountered an error while validating the drop.");
                log.Error($"Error details: {e.Message}");
                return false;
            }
            finally
            {
                if (validFailures != null && validFailures.Any())
                {
                    recorder.RecordTotalErrors(validFailures.ToList());
                }

                // Log telemetry
                recorder.RecordTotalNumberOfPackages(totalNumberOfPackages);
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

        log.Verbose(string.Empty);
        log.Verbose("------------------------------------------------------------");
        log.Verbose("Individual file validation results");
        log.Verbose("------------------------------------------------------------");
        log.Verbose(string.Empty);

        log.Verbose("Additional files not in the manifest: ");
        log.Verbose(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.AdditionalFile).ForEach(f => log.Verbose(f.Path));
        log.Verbose("------------------------------------------------------------");

        log.Verbose("Files with invalid hashes:");
        log.Verbose(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.InvalidHash).ForEach(f => log.Verbose(f.Path));
        log.Verbose("------------------------------------------------------------");

        log.Verbose("Files in the manifest missing from the disk:");
        log.Verbose(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.MissingFile).ForEach(f => log.Verbose(f.Path));
        log.Verbose("------------------------------------------------------------");
        log.Verbose("Unknown file failures:");
        log.Verbose(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.Other).ForEach(f => log.Verbose(f.Path));
        log.Verbose("------------------------------------------------------------");

        if (validFailures.Where(vf => vf.ErrorType == ErrorType.NoPackagesFound).Count() == 1)
        {
            log.Verbose(string.Empty);
            log.Verbose("------------------------------------------------------------");
            log.Verbose("Optional validation results");
            log.Verbose("------------------------------------------------------------");
            log.Verbose(string.Empty);
        
            log.Verbose("No packages found in the manifest.");
            log.Verbose("------------------------------------------------------------");
        }
    }

    private void LogResultsSummary(ValidationResult validationResultOutput, IEnumerable<FileValidationResult> validFailures)
    {
        if (validationResultOutput == null || validFailures == null)
        {
            // We failed to generate the output due to a workflow error.
            return;
        }

        log.Debug(string.Empty);
        log.Debug("------------------------------------------------------------");
        log.Debug("Validation Summary");
        log.Debug("------------------------------------------------------------");
        log.Debug(string.Empty);

        log.Debug($"Validation Result . . . . . . . . . . . . . . . .{validationResultOutput.Result}");
        log.Debug($"Total execution time (sec) . . . . . . . . . . . {validationResultOutput.Summary.TotalExecutionTimeInSeconds}");
        log.Debug($"Files failed . . . . . . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount}");
        log.Debug($"Files successfully validated . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount}");
        log.Debug($"Total files validated. . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesValidatedCount}");
        log.Debug($"Total files in manifest. . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest}");
        log.Debug($"");
        log.Debug($"Additional files not in the manifest . . . . . . {validFailures.Count(v => v.ErrorType == ErrorType.AdditionalFile)}");
        log.Debug($"Files with invalid hashes . . . . . . . . . . . .{validFailures.Count(v => v.ErrorType == ErrorType.InvalidHash)}");
        log.Debug($"Files in the manifest missing from the disk . . .{validFailures.Count(v => v.ErrorType == ErrorType.MissingFile)}");

        if (validFailures.Where(vf => vf.ErrorType == ErrorType.NoPackagesFound).Count() == 1)
        {
            log.Debug($"Optional validation failures . . . . . . . . . . {validFailures.Count(v => v.ErrorType == ErrorType.NoPackagesFound)}");
        }

        log.Debug($"Unknown file failures . . . . . . . . . . . . .  {validFailures.Count(v => v.ErrorType == ErrorType.Other)}");
    }
}