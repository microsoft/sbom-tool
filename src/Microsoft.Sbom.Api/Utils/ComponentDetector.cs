// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// A component detector wrapper, used for unit testing.
/// </summary>
public class ComponentDetector
{
    public virtual async Task<ScanResult> ScanAsync(string[] args)
    {
        var orchestrator = new Orchestrator();
        return await orchestrator.LoadAsync(args);
    }
}