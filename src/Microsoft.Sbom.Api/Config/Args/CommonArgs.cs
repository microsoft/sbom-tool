// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.Config;
using PowerArgs;
using Serilog.Events;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// Defines the common arguments used by all actions of the ManifestTool.
/// </summary>
public abstract class CommonArgs
{
    /// <summary>
    /// Gets or sets the action currently being performed by the manifest tool.
    /// </summary>
    [ArgIgnore]
    public ManifestToolActions ManifestToolAction { get; set; }

    /// <summary>
    /// Gets or sets display this amount of detail in the logging output.
    /// </summary>
    [ArgDescription("Display this amount of detail in the logging output.")]
    public LogEventLevel? Verbosity { get; set; }
}
