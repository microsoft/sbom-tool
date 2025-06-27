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
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Conformance;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;
using PowerArgs;
using Serilog;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;

namespace Microsoft.Sbom.Api.Workflows;

public class SbomValidationWorkflowBase
{
    private readonly IRecorder recorder;
    private readonly ISignValidationProvider signValidationProvider;
    private readonly ILogger log;
    private readonly IManifestParserProvider manifestParserProvider;
    private readonly FilesValidator filesValidator;
    private readonly ValidationResultGenerator validationResultGenerator;
    private readonly IOutputWriter outputWriter;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IOSUtils osUtils;

    public SbomValidationWorkflowBase(IRecorder recorder, ISignValidationProvider signValidationProvider, ILogger log, IManifestParserProvider manifestParserProvider, FilesValidator filesValidator, ValidationResultGenerator validationResultGenerator, IOutputWriter outputWriter, IFileSystemUtils fileSystemUtils, IOSUtils osUtils)
    {
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.signValidationProvider = signValidationProvider ?? throw new ArgumentNullException(nameof(signValidationProvider));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.manifestParserProvider = manifestParserProvider ?? throw new ArgumentNullException(nameof(manifestParserProvider));
        this.filesValidator = filesValidator ?? throw new ArgumentNullException(nameof(filesValidator));
        this.validationResultGenerator = validationResultGenerator ?? throw new ArgumentNullException(nameof(validationResultGenerator));
        this.outputWriter = outputWriter ?? throw new ArgumentNullException(nameof(outputWriter));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
    }

    public async Task<bool> ValidateAsync(ISbomConfig sbomConfig, string eventName, ConformanceType conformanceType, bool validateSignature, bool failIfNoPackages, bool ignoreMissing)
    {
        ValidationResult validationResultOutput = null;
        IEnumerable<FileValidationResult> validFailures = null;
        var totalNumberOfPackages = 0;

        using (recorder.TraceEvent(eventName))
        {
            try
            {
                var sw = Stopwatch.StartNew();
                using var stream = fileSystemUtils.OpenRead(sbomConfig.ManifestJsonFilePath);
                var manifestInterface = manifestParserProvider.Get(sbomConfig.ManifestInfo);
                var sbomParser = manifestInterface.CreateParser(stream);
                sbomParser.EnforceConformance(conformanceType);

                // Validate signature
                if (validateSignature)
                {
                    var signValidator = signValidationProvider.Get();

                    if (signValidator == null)
                    {
                        log.Warning($"ValidateSignature switch is true, but couldn't find a sign validator for the current OS, skipping validation.");
                    }
                    else
                    {
                        Dictionary<string, string> additionalTelemetry = new();
                        var signatureIsValid = signValidator.Validate(additionalTelemetry);
                        RecordAdditionalTelemetry(additionalTelemetry); // TODO make this specific to the event name to differentiate telemetry for different validations
                        if (!signatureIsValid)
                        {
                            log.Error("Sign validation failed.");
                            validFailures = new List<FileValidationResult> { new FileValidationResult { ErrorType = ErrorType.ManifestFileSigningError } };
                            return false;
                        }
                    }
                }

                var successfullyValidatedFiles = 0;
                List<FileValidationResult> fileValidationFailures = null;

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
                                ThrowOnInvalidInputFiles(fileValidationFailures);
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
                                AddInvalidConformanceElementsToFailures(fileValidationFailures, elementsResult.InvalidConformanceElements, conformanceType);
                                ThrowOnInvalidInputFiles(fileValidationFailures);
                                break;
                            default:
                                break;
                        }
                    }
                }
                while (result is not null);

                _ = sbomParser.GetMetadata();

                if (failIfNoPackages && totalNumberOfPackages <= 1)
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

                validFailures = fileValidationFailures.Where(f => !Constants.SkipFailureReportingForErrors.Contains(f.ErrorType));

                if (ignoreMissing)
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
                LogResultsSummary(validationResultOutput, validFailures, conformanceType);
                LogIndividualFileResults(validFailures, conformanceType);
            }
        }
    }

    private void RecordAdditionalTelemetry(IDictionary<string, string> additionalTelemetry)
    {
        foreach (var pair in additionalTelemetry)
        {
            recorder.AddResult(pair.Key, pair.Value);
        }
    }

    private void LogIndividualFileResults(IEnumerable<FileValidationResult> validFailures, ConformanceType conformance)
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

        if (!NoOpConformance(conformance))
        {
            Console.WriteLine($"Elements in the manifest that are non-compliant with {conformance}:");
            Console.WriteLine(string.Empty);
            validFailures.Where(vf => vf.ErrorType == ErrorType.ConformanceError).ForEach(f => Console.WriteLine(f.Path));
            Console.WriteLine("------------------------------------------------------------");
        }

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

    private void LogResultsSummary(ValidationResult validationResultOutput, IEnumerable<FileValidationResult> validFailures, ConformanceType conformance)
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
        if (!NoOpConformance(conformance))
        {
            Console.WriteLine($"Elements in the manifest that are non-compliant with {conformance} . . . " +
            $"{validFailures.Count(v => v.ErrorType == ErrorType.ConformanceError)}");
        }

        if (validFailures.Any(vf => vf.ErrorType == ErrorType.NoPackagesFound))
        {
            Console.WriteLine($"Package validation failures . . . . . . . . . . .{validFailures.Count(v => v.ErrorType == ErrorType.NoPackagesFound)}");
        }

        Console.WriteLine($"Unknown file failures . . . . . . . . . . . . .  {validFailures.Count(v => v.ErrorType == ErrorType.Other)}");
    }

    private void ThrowOnInvalidInputFiles(List<FileValidationResult> fileValidationFailures)
    {
        var invalidInputFiles = fileValidationFailures.Where(f => f.ErrorType == ErrorType.InvalidInputFile).ToList();
        if (invalidInputFiles.Count != 0)
        {
            throw new InvalidDataException($"Your manifest file is malformed. {invalidInputFiles.First().Path}");
        }
    }

    private void AddInvalidConformanceElementsToFailures(List<FileValidationResult> fileValidationFailures, HashSet<InvalidElementInfo> invalidElements, ConformanceType conformance)
    {
        if (invalidElements == null || !invalidElements.Any())
        {
            return;
        }

        switch (conformance.Name)
        {
            case "NTIAMin":
                AddInvalidNTIAMinElementsToFailures(fileValidationFailures, invalidElements);
                break;
            case "None":
                break;
            default:
                break;
        }
    }

    private void AddInvalidNTIAMinElementsToFailures(List<FileValidationResult> fileValidationFailures, HashSet<InvalidElementInfo> invalidElements)
    {
        foreach (var invalidElementInfo in invalidElements)
        {
            fileValidationFailures.Add(new FileValidationResult
            {
                Path = invalidElementInfo.ToString(),
                ErrorType = ErrorType.ConformanceError,
            });
        }
    }

    private bool NoOpConformance(ConformanceType conformance)
    {
        return conformance?.Name == "None";
    }
}
