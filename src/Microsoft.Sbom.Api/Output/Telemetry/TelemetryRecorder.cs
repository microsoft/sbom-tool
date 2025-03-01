// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;
using Serilog;
using Serilog.Core;
using Spectre.Console;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Output.Telemetry;

/// <summary>
/// Records telemetry for an execution of the SBOM tool.
/// </summary>
public class TelemetryRecorder : IRecorder
{
    private readonly ConcurrentBag<TimingRecorder> timingRecorders = new();
    private readonly IDictionary<ManifestInfo, string> sbomFormats = new Dictionary<ManifestInfo, string>();
    private readonly IDictionary<string, object> switches = new Dictionary<string, object>();
    private readonly IList<Exception> exceptions = new List<Exception>();
    private readonly IList<Exception> apiExceptions = new List<Exception>();
    private readonly IList<Exception> metadataExceptions = new List<Exception>();
    private IList<FileValidationResult> errors = new List<FileValidationResult>();
    private Result result = Result.Success;

    private int totalNumberOfPackages = 0;
    private int totalNumberOfLicenses = 0;
    private int packageDetailsEntries = 0;

    public IFileSystemUtils FileSystemUtils { get; }

    public IConfiguration Configuration { get; }

    public ILogger Log { get; }

    public TelemetryRecorder(IFileSystemUtils fileSystemUtils, IConfiguration configuration, ILogger log)
    {
        FileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        Log = log ?? throw new ArgumentNullException(nameof(log));
    }

    private TelemetryRecorder(IConfiguration configuration, IFileSystemUtils fileSystemUtils)
    {
        Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        FileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    /// <summary>
    /// Create an instance of TelemtryRecorder without the need for an ILogger.
    /// </summary>
    /// <param name="configuration">Current configuration of the tool.</param>
    /// <param name="fileSystemUtils">Wrapper around file system functions.</param>
    public static TelemetryRecorder Create(IConfiguration configuration, IFileSystemUtils fileSystemUtils)
    {
        return new TelemetryRecorder(configuration, fileSystemUtils);
    }

    /// <summary>
    /// Method to log telemetry in conditions when the tool is not able to start execution of workflow.
    /// </summary>
    /// <param name="exception">Exception that we want to log.</param>
    public async Task LogException(Exception exception)
    {
        var logger = Log;
        if (Log is null)
        {
            logger = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = Configuration.Verbosity.Value })
                .WriteTo.Console(outputTemplate: Constants.LoggerTemplate)
                .CreateLogger();
        }

        // Convert thrown Exception to list of exceptions for the SbomTelemetry object.
        var exceptionList = new List<Exception>
        {
            exception
        };

        try
        {
            // Create the telemetry object.
            var telemetry = new SbomTelemetry
            {
                Result = Result.Failure,
                Timings = timingRecorders.Select(t => t.ToTiming()).ToList(),
                Switches = this.switches,
                Parameters = Configuration,
                Exceptions = exceptionList.ToDictionary(k => k.GetType().ToString(), v => v.Message),
            };

            // Log to logger.
            logger.Information("Could not start execution of workflow. Logging telemetry {@Telemetry}", telemetry);

            await RecordToFile(telemetry, Configuration.TelemetryFilePath?.Value);
        }
        catch (Exception e)
        {
            // We shouldn't fail the main workflow due to some failure on the telemetry generation.
            // Just log the result and return silently.
            logger.Warning($"Failed to log telemetry. Exception: {e.Message}");
        }
    }

    public IList<FileValidationResult> Errors => errors;

    /// <summary>
    /// Start recording the duration of exeuction of the given event.
    /// </summary>
    /// <param name="eventName">The event name.</param>
    /// <returns>A disposable <see cref="TimingRecorder"/> object.</returns>
    public TimingRecorder TraceEvent(string eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
        {
            throw new ArgumentException($"'{nameof(eventName)}' cannot be null or whitespace.", nameof(eventName));
        }

        var timingRecorder = new TimingRecorder(eventName);
        timingRecorders.Add(timingRecorder);
        return timingRecorder;
    }

    /// <summary>
    /// Record the total errors encountered during the execution of the SBOM tool.
    /// </summary>
    /// <param name="errors">A list of errors.</param>
    /// <exception cref="ArgumentNullException">If the errors object is null.</exception>
    public void RecordTotalErrors(IList<FileValidationResult> errors)
    {
        this.errors = errors ?? throw new ArgumentNullException(nameof(errors));
    }

    /// <inheritdoc/>
    public void RecordSbomFormat(ManifestInfo manifestInfo, string sbomFilePath)
    {
        if (manifestInfo is null)
        {
            throw new ArgumentNullException(nameof(manifestInfo));
        }

        if (string.IsNullOrWhiteSpace(sbomFilePath))
        {
            throw new ArgumentException($"'{nameof(sbomFilePath)}' cannot be null or whitespace.", nameof(sbomFilePath));
        }

        this.sbomFormats[manifestInfo] = sbomFilePath;
    }

    /// <summary>
    /// Write telemetry object to the telemetryFilePath.
    /// </summary>
    /// <param name="telemetry">The telemetry object to be written to the file.</param>
    /// /// <param name="telemetryFilePath">The file path we want to write the telemetry to.</param>
    private async Task RecordToFile(SbomTelemetry telemetry, string telemetryFilePath)
    {
        // Write to file.
        if (!string.IsNullOrWhiteSpace(telemetryFilePath))
        {
            using (var fileStream = FileSystemUtils.OpenWrite(telemetryFilePath))
            {
                var options = new JsonSerializerOptions
                {
                    Converters =
                    {
                            new JsonStringEnumConverter()
                    }
                };
                await JsonSerializer.SerializeAsync(fileStream, telemetry, options);
            }
        }
    }

    /// <summary>
    /// Record any exception that was encountered during the execution of the tool.
    /// </summary>
    /// <param name="exception">The exception that was encountered.</param>
    /// <exception cref="ArgumentNullException">If the exception is null.</exception>
    public void RecordException(Exception exception)
    {
        if (exception is null)
        {
            throw new ArgumentNullException(nameof(exception));
        }

        this.exceptions.Add(exception);
    }

    /// <summary>
    /// Record any exception that was encountered during API calls.
    /// </summary>
    /// <param name="exception">The exception that was encountered.</param>
    /// <exception cref="ArgumentNullException">If the exception is null.</exception>
    public void RecordAPIException(Exception apiException)
    {
        if (apiException is null)
        {
            throw new ArgumentNullException(nameof(apiException));
        }

        this.apiExceptions.Add(apiException);
    }

    /// <summary>
    /// Record any exception that was encountered during the detection or parsing of individual package metadata files.
    /// </summary>
    /// <param name="exception">The exception that was encountered.</param>
    /// <exception cref="ArgumentNullException">If the exception is null.</exception>
    public void RecordMetadataException(Exception metadataException)
    {
        if (metadataException is null)
        {
            throw new ArgumentNullException();
        }

        this.metadataExceptions.Add(metadataException);
    }

    /// <summary>
    /// Record the total number of packages that were processed during the execution of the SBOM tool.
    /// </summary>
    /// <param name="packageCount">The total package count after execution.</param>
    public void RecordTotalNumberOfPackages(int packageCount)
    {
        this.totalNumberOfPackages = packageCount;
    }

    /// <summary>
    /// Adds onto the total number of packageDetail entries found by the PackageDetailsFactory.
    /// </summary>
    /// <param name="packageDetailsCount">The total packageDetails count after execution of the PackageDetailsFactory.</param>
    public void AddToTotalNumberOfPackageDetailsEntries(int packageDetailsCount)
    {
        Interlocked.Add(ref this.packageDetailsEntries, packageDetailsCount);
    }

    /// <summary>
    /// Adds onto the total count of licenses that were retrieved from the API.
    /// </summary>
    /// <param name="licenseCount">The count of licenses that are to be added to the total.</param>
    public void AddToTotalCountOfLicenses(int licenseCount)
    {
        Interlocked.Add(ref this.totalNumberOfLicenses, licenseCount);
    }

    /// <summary>
    /// Record a switch that was used during the execution of the SBOM tool.
    /// </summary>
    /// <param name="switchName">The name of the switch or environment variable.</param>
    /// <param name="value">The value of the variable.</param>
    /// <exception cref="ArgumentException">If the switch name is null or whitespace.</exception>
    /// <exception cref="ArgumentNullException">If the value is empty.</exception>
    public void RecordSwitch(string switchName, object value)
    {
        if (string.IsNullOrWhiteSpace(switchName))
        {
            throw new ArgumentException($"'{nameof(switchName)}' cannot be null or whitespace.", nameof(switchName));
        }

        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        this.switches.Add(switchName, value);
    }

    /// <summary>
    /// Finalize the recorder, and log the telemetry.
    /// </summary>
    public async Task FinalizeAndLogTelemetryAsync()
    {
        try
        {
            // Calculate result
            if (this.errors.Any() || this.exceptions.Any())
            {
                this.result = Result.Failure;
            }

            // Calculate SBOM file sizes.
            var sbomFormatsUsed = sbomFormats
                .Where(f => File.Exists(f.Value))
                .Select(f => new SbomFile
                {
                    SbomFilePath = f.Value,
                    SbomFormatName = f.Key,
                    FileSizeInBytes = new FileInfo(f.Value).Length,
                    TotalNumberOfPackages = this.totalNumberOfPackages
                })
                .ToList();

            // Create the telemetry object.
            var telemetry = new SbomTelemetry
            {
                Result = this.result,
                Errors = new ErrorContainer<FileValidationResult>
                {
                    Errors = this.errors,
                    Count = this.errors.Count
                },
                Timings = timingRecorders.Select(t => t.ToTiming()).ToList(),
                Parameters = Configuration,
                SbomFormatsUsed = sbomFormatsUsed,
                Switches = this.switches,
                Exceptions = this.exceptions.GroupBy(e => e.GetType().ToString()).ToDictionary(group => group.Key, group => group.First().Message),
                APIExceptions = this.apiExceptions.GroupBy(e => e.GetType().ToString()).ToDictionary(group => group.Key, group => group.First().Message),
                MetadataExceptions = this.metadataExceptions.GroupBy(e => e.GetType().ToString()).ToDictionary(g => g.Key, g => g.First().Message),
                TotalLicensesDetected = this.totalNumberOfLicenses,
                PackageDetailsEntries = this.packageDetailsEntries
            };

            // Log to logger.
            Log.Debug($"Wrote telemetry object to path {Configuration.TelemetryFilePath?.Value}");

            if (Configuration.ManifestToolAction == ManifestToolActions.Generate && Configuration.BuildComponentPath?.Value != null && this.totalNumberOfPackages == 0)
            {
                Log.Warning("0 Packages were detected during the {Action} workflow.", Configuration.ManifestToolAction);
            }

            Log.Information("Finished execution of the {Action} workflow {@Telemetry}", Configuration.ManifestToolAction, telemetry);

            await RecordToFile(telemetry, Configuration.TelemetryFilePath?.Value);
        }
        catch (Exception ex)
        {
            // We should'nt fail the main workflow due to some failure on the telemetry generation.
            // Just log the result and return silently.
            Log.Warning($"Failed to log telemetry. Exception: {ex.Message}");
        }
    }
}
