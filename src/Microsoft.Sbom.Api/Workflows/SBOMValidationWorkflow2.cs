using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using PowerArgs;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows
{
    public class SBOMValidationWorkflow2 : IWorkflow
    {
        private readonly IRecorder recorder;
        private readonly ISignValidator signValidator;
        private readonly ILogger log;
        private readonly IManifestInterface manifestInterface;
        private readonly IConfiguration configuration;
        private readonly ISbomConfigProvider sbomConfigs;
        private readonly NullExecutor nullExecutor;

        public SBOMValidationWorkflow2(IRecorder recorder, ISignValidator signValidator, ILogger log, IManifestInterface manifestInterface, IConfiguration configuration, ISbomConfigProvider sbomConfigs, NullExecutor nullExecutor)
        {
            this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
            this.signValidator = signValidator ?? throw new ArgumentNullException(nameof(signValidator));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.manifestInterface = manifestInterface ?? throw new ArgumentNullException(nameof(manifestInterface));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
            this.nullExecutor = nullExecutor ?? throw new ArgumentNullException(nameof(nullExecutor));
        }

        public Task<bool> RunAsync()
        {
            ValidationResult validationResultOutput = null;
            IEnumerable<FileValidationResult> validFailures = null;

            using (recorder.TraceEvent(Events.SBOMValidationWorkflow))
            {
                try
                {
                    var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo.Value.FirstOrDefault());

                    using Stream stream = File.OpenRead(sbomConfig.ManifestJsonFilePath);
                    var sbomParser = manifestInterface.CreateParser(stream);

                    // Validate signature
                    if (!signValidator.Validate())
                    {
                        log.Error("Sign validation failed.");
                        return null;
                    }

                    while (sbomParser.Next() != Contracts.Enums.ParserState.FINISHED)
                    {

                        switch (sbomParser.CurrentState)
                        {
                            case Contracts.Enums.ParserState.FILES:

                                sbomParser.GetFiles().ToList();
                                break;
                            case Contracts.Enums.ParserState.PACKAGES:
                                sbomParser.GetPackages().ToList();
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



                    return null;

                }
                catch (Exception e)
                {
                    recorder.RecordException(e);
                    log.Error("Encountered an error while validating the drop.");
                    log.Error($"Error details: {e.Message}");
                    return null;
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
            log.Debug($"Unknown file failures . . . . . . . . . . . . .  {validFailures.Count(v => v.ErrorType == ErrorType.Other)}");
        }
    }
}
