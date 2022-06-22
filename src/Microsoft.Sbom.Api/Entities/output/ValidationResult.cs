// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Entities.output
{
    /// <summary>
    /// The final result JSON that is serialized to the output location.
    /// </summary>
    public class ValidationResult
    {
        /// <summary>
        /// Gets or sets the <see cref="Result"/> of the validation.
        /// </summary>
        public Result Result { get; set; }

        /// <summary>
        /// Gets or sets a list of <see cref="FileValidationResult"/>s.
        /// </summary>
        public ErrorContainer<FileValidationResult> ValidationErrors { get; set; }

        /// <summary>
        /// Gets or sets metadata and telemetry for this validation.
        /// </summary>
        public Summary Summary { get; set; }
    }
}
