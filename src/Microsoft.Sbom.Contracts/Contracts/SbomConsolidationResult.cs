// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Represents the result of a SBOM generation action.
/// </summary>
public class SbomConsolidationResult
{
    /// <summary>
    /// Indicaties whether the SBOM consolidation was successful
    /// </summary>
    public bool IsSuccessful { get; set; }
}
