// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Output.Telemetry;

/// <summary>
/// Records telemetry for the SBOM tool.
/// </summary>
public interface IRecorder
{
    /// <summary>
    /// Start recording the duration of exeuction of the given event.
    /// </summary>
    /// <param name="eventName">The event name.</param>
    /// <returns>A disposable <see cref="TimingRecorder"/> object.</returns>
    public TimingRecorder TraceEvent(string eventName);

    /// <summary>
    /// Record the total errors encountered during the execution of the SBOM tool.
    /// </summary>
    /// <param name="errors">A list of errors.</param>
    /// <exception cref="ArgumentNullException">If the errors object is null.</exception>
    public void RecordTotalErrors(IList<FileValidationResult> errors);

    /// <summary>
    /// Record the total number of unique packages that were detected during the execution of the SBOM tool.
    /// </summary>
    /// <param name="packages">Total number of packages encountered while validating the SBOM.</param>
    public void RecordTotalNumberOfPackages(int count);

    /// <summary>
    /// Adds onto the total count of licenses that were retrieved from the API.
    /// </summary>
    /// <param name="count">Count of licenses to be added.</param>
    public void AddToTotalCountOfLicenses(int count);

    /// <summary>
    /// Records a SBOM format that we used during the execution of the SBOM tool.
    /// </summary>
    /// <param name="manifestInfo">The SBOM format as a <see cref="ManifestInfo"/> object.</param>
    /// <param name="sbomFilePath">The path where the generated SBOM is stored.</param>
    /// <exception cref="ArgumentNullException">If the manifestInfo object is null.</exception>
    public void RecordSBOMFormat(ManifestInfo manifestInfo, string sbomFilePath);

    /// <summary>
    /// Record a switch that was used during the execution of the SBOM tool.
    /// </summary>
    /// <param name="switchName">The name of the switch or environment variable.</param>
    /// <param name="value">The value of the variable.</param>
    /// <exception cref="ArgumentException">If the switch name is null or whitespace.</exception>
    /// <exception cref="ArgumentNullException">If the value is empty.</exception>
    public void RecordSwitch(string switchName, object value);

    /// <summary>
    /// Record any exception that was encountered during the execution of the tool.
    /// </summary>
    /// <param name="exception">The exception that was encountered.</param>
    /// <exception cref="ArgumentNullException">If the exception is null.</exception>
    public void RecordException(Exception exception);

    /// <summary>
    /// Record any exception that was encountered during the execution of API calls.
    /// </summary>
    /// <param name="exception">The exception that was encountered.</param>
    /// <exception cref="ArgumentNullException">If the exception is null.</exception>
    public void RecordAPIException(Exception exception);

    /// <summary>
    /// Finalize the recorder, and log the telemetry.
    /// </summary>
    public Task FinalizeAndLogTelemetryAsync();

    public IList<FileValidationResult> Errors { get; }
}
