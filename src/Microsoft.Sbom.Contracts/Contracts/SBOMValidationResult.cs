// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Contracts;

using System.Collections.Generic;

/// <summary>
/// Represents the result of a SBOM validation action.
/// </summary>
public class SBOMValidationResult
{
    public bool IsSuccess { get; private set; }

    public IList<EntityError> Errors { get; private set; }

    public SBOMValidationResult(bool isSuccess, IList<EntityError> errors)
    {
        this.IsSuccess = isSuccess;
        this.Errors = errors;
    }
}
