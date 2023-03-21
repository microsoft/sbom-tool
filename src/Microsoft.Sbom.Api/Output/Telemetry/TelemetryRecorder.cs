// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;
using PowerArgs;
using System.IO;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Output.Telemetry
{
    /// <summary>
    /// Records telemetry for an execution of the SBOM tool.
    /// </summary>
    public class TelemetryRecorder : IRecorder
    {
        private readonly ConcurrentBag<TimingRecorder> timingRecorders = new ConcurrentBag<TimingRecorder>();
        private readonly IDictionary<ManifestInfo, string> sbomFormats = new Dictionary<ManifestInfo, string>();
        private readonly IDictionary<string, object> switches = new Dictionary<string, object>();
        private readonly IList<Exception> exceptions = new List<Exception>();

        private IList<FileValidationResult> errors = new List<FileValidationResult>();
        private Result result = Result.Success;

        public IFileSystemUtils FileSystemUtils { get; }

        public IConfiguration Configuration { get; }

        public ILogger Log { get; }

        public TelemetryRecorder(IFileSystemUtils fileSystemUtils, IConfiguration configuration, ILogger log)
        {
            FileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Log = log ?? throw new ArgumentNullException(nameof(log));
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

            TimingRecorder timingRecorder = new TimingRecorder(eventName);
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
        public void RecordSBOMFormat(ManifestInfo manifestInfo, string sbomFilePath)
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
        /// Record any exception that was encountered during the exection of the tool.
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
                                        .Select(f => new SBOMFile
                                        {
                                            SbomFilePath = f.Value,
                                            SbomFormatName = f.Key,
                                            FileSizeInBytes = new System.IO.FileInfo(f.Value).Length
                                        })
                                        .ToList();

                // Create the telemetry object.
                var telemetry = new SBOMTelemetry
                {
                    Result = this.result,
                    Errors = new ErrorContainer<FileValidationResult>
                    {
                        Errors = this.errors,
                        Count = this.errors.Count
                    },
                    Timings = timingRecorders.Select(t => t.ToTiming()).ToList(),
                    Parameters = Configuration,
                    SBOMFormatsUsed = sbomFormatsUsed,
                    Switches = this.switches,
                    Exceptions = this.exceptions.ToDictionary(k => k.GetType().ToString(), v => v.Message)
                };

                // Log to logger.
                Log.Information("Finished execution of the {Action} workflow {@Telemetry}", Configuration.ManifestToolAction, telemetry);

                // Write to file.
                if (!string.IsNullOrWhiteSpace(Configuration.TelemetryFilePath?.Value))
                {
                    using (var fileStream = FileSystemUtils.OpenWrite(Configuration.TelemetryFilePath.Value))
                    {
                        var options = new JsonSerializerOptions
                        {
                            Converters =
                        {
                            new JsonStringEnumConverter()
                        }
                        };
                        await JsonSerializer.SerializeAsync(fileStream, telemetry, options);
                        Log.Debug($"Wrote telemetry object to path {Configuration.TelemetryFilePath.Value}");
                    }
                }
            }
            catch (Exception ex)
            {
                // We should'nt fail the main workflow due to some failure on the telemetry generation.
                // Just log the result and return silently.
                Log.Warning($"Failed to log telemetry. Exception: {ex.Message}");
            }
        }
    }
}
