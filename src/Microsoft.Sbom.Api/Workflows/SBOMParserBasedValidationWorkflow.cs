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
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;
using PowerArgs;
using Serilog;
using ApiConstants = Microsoft.Sbom.Api.Utils.Constants;

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
    private readonly IOSUtils osUtils;

    public SbomParserBasedValidationWorkflow(IRecorder recorder, ISignValidationProvider signValidationProvider, ILogger log, IManifestParserProvider manifestParserProvider, IConfiguration configuration, ISbomConfigProvider sbomConfigs, FilesValidator filesValidator, ValidationResultGenerator validationResultGenerator, IOutputWriter outputWriter, IFileSystemUtils fileSystemUtils, IOSUtils osUtils)
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
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
    }

    public async Task<bool> RunAsync()
    {
        ValidationResult validationResultOutput = null;
        IEnumerable<FileValidationResult> validFailures = null;
        var totalNumberOfPackages = 0;

        using (recorder.TraceEvent(Events.SBOMValidationWorkflow))
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo.Value.FirstOrDefault());
                using var stream = fileSystemUtils.OpenRead(sbomConfig.ManifestJsonFilePath);
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
                            validFailures = new List<FileValidationResult> { new FileValidationResult { ErrorType = ErrorType.ManifestFileSigningError } };
                            return false;
                        }
                    }
                }

                // Validate compliance standard for SPDX 3.0 parsers and above
                if (!string.IsNullOrEmpty(configuration.ComplianceStandard?.Value) && Convert.ToDouble(sbomConfig.ManifestInfo.Version) >= 3.0)
                {
                    var complianceStandard = configuration.ComplianceStandard.Value;
                    try
                    {
                        ((SPDX30Parser)sbomParser).RequiredComplianceStandard = complianceStandard;
                    }
                    catch (Exception e)
                    {
                        recorder.RecordException(e);
                        log.Error($"Unable to use the given compliance standard {complianceStandard} to parse the SBOM.");
                    }
                }

                var successfullyValidatedFiles = 0;
                List<FileValidationResult> fileValidationFailures = null;

                // This logic is the same as SbomParserTestsBase, however since that logic is part of the test suite we replicate it here
                ParserStateResult? result = null;
                do
                {
                    result = sbomParser.Next();
                    if (result is not null)
                    {
                        switch (result)
                        {
                            case FilesResult filesResult:
                                (successfullyValidatedFiles, fileValidationFailures) = await filesValidator.Validate(filesResult.Files);
                                ValidateInvalidInputFiles(fileValidationFailures);
                                break;
                            case PackagesResult packagesResult:
                                var packages = packagesResult.Packages.ToList();
                                totalNumberOfPackages = packages.Count();
                                break;
                            case RelationshipsResult relationshipsResult:
                                relationshipsResult.Relationships.ToList();
                                break;
                            case ExternalDocumentReferencesResult externalRefResult:
                                externalRefResult.References.ToList();
                                break;
                            case ContextsResult contextsResult:
                                contextsResult.Contexts.ToList();
                                break;
                            case ElementsResult elementsResult:
                                elementsResult.Elements.ToList();
                                totalNumberOfPackages = elementsResult.PackagesCount;

                                (successfullyValidatedFiles, fileValidationFailures) = await filesValidator.Validate(elementsResult.Files);
                                ValidateInvalidInputFiles(fileValidationFailures);
                                break;
                            default:
                                break;
                        }
                    }
                }
                while (result is not null);

                _ = sbomParser.GetMetadata();

                if (configuration.FailIfNoPackages?.Value == true && totalNumberOfPackages <= 1)
                {
                    fileValidationFailures.Add(new FileValidationResult
                    {
                        ErrorType = ErrorType.NoPackagesFound
                    });
                }

                log.Debug("Finished workflow, gathering results.");

                // Generate JSON output
                validationResultOutput = validationResultGenerator
                    .WithTotalFilesInManifest(sbomConfig.Recorder.GetGenerationData().Checksums.Count())
                    .WithTotalPackagesInManifest(totalNumberOfPackages)
                    .WithSuccessCount(successfullyValidatedFiles)
                    .WithTotalDuration(sw.Elapsed)
                    .WithValidationResults(fileValidationFailures)
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

                validFailures = fileValidationFailures.Where(f => !ApiConstants.SkipFailureReportingForErrors.Contains(f.ErrorType));

                if (configuration.IgnoreMissing.Value)
                {
                    log.Warning("Not including missing files on disk as -IgnoreMissing switch is on.");
                    validFailures = validFailures.Where(a => a.ErrorType != ErrorType.MissingFile);
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
        if (validFailures == null || validFailures.Any(v => v.ErrorType == ErrorType.ManifestFileSigningError))
        {
            // We failed to generate the output due to a workflow error.
            return;
        }

        var caseSensitiveComment = !validFailures.Any() || this.osUtils.IsCaseSensitiveOS() ?
            string.Empty :
            "\r\n  Note: If the manifest file was originally created using a" +
            "\r\n        case-sensitive OS, you may also need to validate it" +
            "\r\n        using a case-sensitive OS.";

        Console.WriteLine(string.Empty);
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine($"Individual file validation results{caseSensitiveComment}");
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine(string.Empty);

        Console.WriteLine("Additional files not in the manifest: ");
        Console.WriteLine(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.AdditionalFile).ForEach(f => Console.WriteLine(f.Path));
        Console.WriteLine("------------------------------------------------------------");

        Console.WriteLine("Files with invalid hashes:");
        Console.WriteLine(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.InvalidHash).ForEach(f => Console.WriteLine(f.Path));
        Console.WriteLine("------------------------------------------------------------");

        Console.WriteLine("Files in the manifest missing from the disk:");
        Console.WriteLine(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.MissingFile).ForEach(f => Console.WriteLine(f.Path));
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine("Unknown file failures:");
        Console.WriteLine(string.Empty);
        validFailures.Where(vf => vf.ErrorType == ErrorType.Other).ForEach(f => Console.WriteLine(f.Path));
        Console.WriteLine("------------------------------------------------------------");

        if (validFailures.Any(vf => vf.ErrorType == ErrorType.NoPackagesFound))
        {
            Console.WriteLine("Package validation results:");
            Console.WriteLine(string.Empty);
            Console.WriteLine("No packages found in the manifest");
            Console.WriteLine("------------------------------------------------------------");
        }
    }

    private void LogResultsSummary(ValidationResult validationResultOutput, IEnumerable<FileValidationResult> validFailures)
    {
        if (validationResultOutput == null || validFailures == null || validFailures.Any(v => v.ErrorType == ErrorType.ManifestFileSigningError))
        {
            // We failed to generate the output due to a workflow error.
            return;
        }

        Console.WriteLine(string.Empty);
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine("Validation Summary");
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine(string.Empty);

        Console.WriteLine($"Validation Result . . . . . . . . . . . . . . . .{validationResultOutput.Result}");
        Console.WriteLine($"Total execution time (sec) . . . . . . . . . . . {validationResultOutput.Summary.TotalExecutionTimeInSeconds}");
        Console.WriteLine($"Files failed . . . . . . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesFailedCount}");
        Console.WriteLine($"Files successfully validated . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesSuccessfulCount}");
        Console.WriteLine($"Total files validated. . . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.FilesValidatedCount}");
        Console.WriteLine($"Total files in manifest. . . . . . . . . . . . . {validationResultOutput.Summary.ValidationTelemetery.TotalFilesInManifest}");
        Console.WriteLine($"");
        Console.WriteLine($"Additional files not in the manifest . . . . . . {validFailures.Count(v => v.ErrorType == ErrorType.AdditionalFile)}");
        Console.WriteLine($"Files with invalid hashes . . . . . . . . . . . .{validFailures.Count(v => v.ErrorType == ErrorType.InvalidHash)}");
        Console.WriteLine($"Files in the manifest missing from the disk . . .{validFailures.Count(v => v.ErrorType == ErrorType.MissingFile)}");

        if (validFailures.Any(vf => vf.ErrorType == ErrorType.NoPackagesFound))
        {
            Console.WriteLine($"Package validation failures . . . . . . . . . . .{validFailures.Count(v => v.ErrorType == ErrorType.NoPackagesFound)}");
        }

        Console.WriteLine($"Unknown file failures . . . . . . . . . . . . .  {validFailures.Count(v => v.ErrorType == ErrorType.Other)}");
    }

    private void ValidateInvalidInputFiles(List<FileValidationResult> fileValidationFailures)
    {
        var invalidInputFiles = fileValidationFailures.Where(f => f.ErrorType == ErrorType.InvalidInputFile).ToList();
        if (invalidInputFiles.Count != 0)
        {
            throw new InvalidDataException($"Your manifest file is malformed. {invalidInputFiles.First().Path}");
        }
    }
}
