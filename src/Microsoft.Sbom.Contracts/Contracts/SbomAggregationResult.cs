// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Represents the result of a SBOM aggregation action.
/// </summary>
public class SbomAggregationResult
{
    /// <summary>
    /// Indicates whether the SBOM aggregation was successful.
    /// </summary>
    public bool IsSuccessful { get; }

    /// <summary>
    /// Gets a list of errors that were encountered during the SBOM aggregation.
    /// </summary>
    public IList<EntityError> Errors { get; }

    public SbomAggregationResult(bool isSuccessful, IList<EntityError> errors)
    {
        IsSuccessful = isSuccessful;
        Errors = errors ?? [];
    }
}
