// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Output.Telemetry.Entities;

/// <summary>
/// The telemetry that is logged to a file/console for the given SBOM execution.
/// </summary>
[Serializable]
public class SBOMTelemetry
{
    /// <summary>
    /// Gets or sets the result of the execution.
    /// </summary>
    public Result Result { get; set; }

    /// <summary>
    /// Gets or sets a list of <see cref="FileValidationResult"/>s that was encountered during the execution.
    /// </summary>
    public ErrorContainer<FileValidationResult> Errors { get; set; }

    /// <summary>
    /// Gets or sets a list of <see cref="ConfigurationSetting{T}"/> representing each input parameter used
    /// in the validation.
    /// </summary>
    public IConfiguration Parameters { get; set; }

    /// <summary>
    /// Gets or sets a list of the SBOM formats and related file properties that was used in the
    /// generation/validation of the SBOM.
    /// </summary>
    public IList<SBOMFile> SBOMFormatsUsed { get; set; }

    /// <summary>
    /// Gets or sets a list of event time durations.
    /// </summary>
    public IList<Timing> Timings { get; set; }

    /// <summary>
    /// Gets or sets any internal switches and their value that were used during the execution.
    /// A switch can be something that was provided through a configuraiton or an environment
    /// variable.
    /// </summary>
    public IDictionary<string, object> Switches { get; set; }

    /// <summary>
    /// Gets or sets if any exceptions were thrown, this shows the name of the exception and the error message
    /// of the exception.
    /// </summary>
    public IDictionary<string, string> Exceptions { get; set; }
}
