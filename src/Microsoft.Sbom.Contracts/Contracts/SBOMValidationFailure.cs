// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents a failure result for SBOM validation.
    /// </summary>
    public class SBOMValidationFailure : SBOMValidationResult
    {
        /// <summary>
        /// Gets a list of errors that were encountered during the SBOM validation.
        /// </summary>
        public IList<EntityError> Errors { get; private set; }

        public SBOMValidationFailure(IList<EntityError> errors)
        {
            Errors = errors;
        }
    }
}
