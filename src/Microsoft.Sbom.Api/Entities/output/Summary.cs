// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Entities.Output;

/// <summary>
/// The summary section specifies telemetry and other metadata about the validation.
/// </summary>
public class Summary
{
    /// <summary>
    /// Gets or sets the total time it took to run the validation.
    /// </summary>
    public double TotalExecutionTimeInSeconds { get; set; }

    /// <summary>
    /// Gets or sets a <see cref="ValidationTelemetery"/> representing the validation telemetry.
    /// </summary>
    public ValidationTelemetry ValidationTelemetery { get; set; }

    /// <summary>
    /// Gets or sets a list of <see cref="ConfigurationSetting{T}"/> representing each input parameter used
    /// in the validation.
    /// </summary>
    public IConfiguration Parameters { get; set; }
}
