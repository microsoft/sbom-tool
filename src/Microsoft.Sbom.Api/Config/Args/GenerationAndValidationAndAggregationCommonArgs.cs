// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// Defines the common arguments used by the validation, generation, and aggregation actions of the ManifestTool.
/// </summary>
public abstract class GenerationAndValidationAndAggregationCommonArgs : CommonArgs
{
    /// <summary>
    /// Gets or sets a JSON config file that can be used to specify all the arguments for an action.
    /// </summary>
    [ArgDescription("The json file that contains the configuration for the DropValidator.")]
    public string ConfigFilePath { get; set; }

    [ArgShortcut("t")]
    [ArgDescription("Specify a file where we should write detailed telemetry for the workflow.")]
    public string TelemetryFilePath { get; set; }
}
