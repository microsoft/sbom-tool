// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config;
using PowerArgs;
using Serilog.Events;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Config.Args
{
    /// <summary>
    /// Defines the common arguments used by all actions of the ManifestTool.
    /// </summary>
    public class CommonArgs
    {
        /// <summary>
        /// Gets or sets display this amount of detail in the logging output.
        /// </summary>
        [ArgDescription("Display this amount of detail in the logging output.")]
        public LogEventLevel? Verbosity { get; set; }

        /// <summary>
        /// Gets or sets the number of parallel threads to use for the workflows.
        /// </summary>
        [ArgDescription("The number of parallel threads to use for the workflows.")]
        public int? Parallelism { get; set; }

        /// <summary>
        /// Gets or sets a JSON config file that can be used to specify all the arguments for an action.
        /// </summary>
        [ArgDescription("The json file that contains the configuration for the SbomTool.")]
        public string ConfigFilePath { get; set; }

        /// <summary>
        /// Gets or sets the action currently being performed by the manifest tool.
        /// </summary>
        [ArgIgnore]
        public ManifestToolActions ManifestToolAction { get; set; }

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
}
