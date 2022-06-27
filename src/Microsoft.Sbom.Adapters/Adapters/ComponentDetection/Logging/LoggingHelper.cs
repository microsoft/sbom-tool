// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Adapters.Report;

namespace Microsoft.Sbom.Adapters.Adapters.ComponentDetection.Logging
{
    /// <summary>
    /// A set of static helper methods used by the component detection adapter for logging.
    /// </summary>
    public static class LoggingHelper
    {
        /// <summary>
        /// Used to log that a null component parameter was passed to the adapter.
        /// </summary>
        public static void LogNullComponent(this AdapterReport report, string adapter)
        {
            report.LogFailure($"Null component provided to '{adapter}' adapter.");
        }

        /// <summary>
        /// Logs that no conversion was found for a given <see cref="TypedComponent"/>.
        /// </summary>
        public static void LogNoConversionFound(this AdapterReport report, Type receivedType, TypedComponent component)
        {
            report.LogFailure($"No conversion has been defined for type {receivedType}.  Could not convert component id '{component.Id}'.");
        }
    }
}
