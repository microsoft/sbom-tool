// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions.Entities;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// Defines the common arguments used by the validation and generation actions of the ManifestTool.
/// </summary>
public abstract class GenerationAndValidationCommonArgs : GenerationAndValidationAndAggregationCommonArgs
{
    /// <summary>
    /// Gets or sets the number of parallel threads to use for the workflows.
    /// </summary>
    [ArgDescription("The number of parallel threads to use for the workflows.")]
    public int? Parallelism { get; set; }

    [ArgShortcut("t")]
    [ArgDescription("Specify a file where we should write detailed telemetry for the workflow.")]
    public string TelemetryFilePath { get; set; }

    /// <summary>
    /// Gets or sets if set to false, we will not follow symlinks while traversing the build drop folder. Default is set to 'true'.
    /// </summary>
    [ArgDescription("If set to false, we will not follow symlinks while traversing the build drop folder. Default is set to 'true'.")]
    public bool? FollowSymlinks { get; set; }

    /// <summary>
    /// Gets or sets the name and version of the manifest format that we are using.
    /// </summary>
    [ArgDescription("A list of the name and version of the manifest format that we are using.")]
    [ArgShortcut("mi")]
    public IList<ManifestInfo> ManifestInfo { get; set; }
}
