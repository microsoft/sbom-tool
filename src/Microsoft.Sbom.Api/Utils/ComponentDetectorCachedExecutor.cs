﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Serilog;
using System;
using System.Collections.Concurrent;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Wrapper class for a component detector that caches CD execution results with the same arguments.
    /// The main use case for it is to reuse scanned component results across different providers (e.g packages, external document refs).
    /// </summary>
    public class ComponentDetectorCachedExecutor
    {
        private readonly ILogger log;
        private readonly ComponentDetector detector;
        private ConcurrentDictionary<int, ScanResult> results;

        public ComponentDetectorCachedExecutor(ILogger log, ComponentDetector detector)
        {
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.detector = detector ?? throw new ArgumentNullException(nameof(detector));

            results = new ConcurrentDictionary<int, ScanResult>();
        }

        /// <summary>
        /// Performs component detection scan or gets results from cache based on provided arguments.
        /// </summary>
        /// <param name="args">CD arguments.</param>
        /// <returns>Result of CD scan.</returns>
        public virtual ScanResult Scan(string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            var argsHashCode = string.Join(string.Empty, args).GetHashCode();
            if (results.ContainsKey(argsHashCode))
            {
                log.Debug("Using cached CD scan result for the call with the same arguments");
                return results[argsHashCode];
            }

            var result = detector.Scan(args);
            results.TryAdd(argsHashCode, result);
            return result;
        }
    }
}
