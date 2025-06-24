// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Provides an API interface to the SBOM consolidator workflow.
/// </summary>
public interface ISbomConsolidator
{
    /// <summary>
    /// Consolidate multiple SBOMs into a single SBOM.
    /// </summary>
    public Task<SbomConsolidationResult> ConsolidateSbomsAsync();
}
