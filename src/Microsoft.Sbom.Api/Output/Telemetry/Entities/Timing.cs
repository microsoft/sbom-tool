// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Output.Telemetry.Entities
{
    /// <summary>
    /// Records various time spans for a given event.
    /// </summary>
    [Serializable]
    public class Timing
    {
        /// <summary>
        /// Gets or sets the name of the event.
        /// </summary>
        public string EventName { get; set; }

        /// <summary>
        /// Gets or sets the duration it took to execute the event.
        /// </summary>
        public string TimeSpan { get; set; } 
    }
}
