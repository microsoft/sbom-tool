// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// A component detector wrapper, used for unit testing.
    /// </summary>
    public class ComponentDetector
    {
        public virtual ScanResult Scan(string [] args)
        {
            var orchestrator = new Orchestrator();
            return orchestrator.Load(args);
        }
    }
}
