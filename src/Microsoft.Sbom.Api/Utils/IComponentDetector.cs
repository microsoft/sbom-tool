// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator.Commands;

namespace Microsoft.Sbom.Api.Utils;

public interface IComponentDetector
{
    Task<ScanResult> ScanAsync(ScanSettings args);
}
