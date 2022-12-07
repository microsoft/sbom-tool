// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents the result of an SBOM execution.
    /// </summary>
    public class SBOMResult
    {
        /// <summary>
        /// If true, indicates that the SBOM action was successful.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// Gets a list of errors that were encountered during the execution of the SBOM action.
        /// </summary>
        public IList<EntityError> Errors { get; private set; }

        public SBOMResult(bool isSuccessful, IList<EntityError> errors)
        {
            IsSuccessful = isSuccessful;
            Errors = errors ?? new List<EntityError>();
        }
    }
}
