using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents the result of a SBOM validation action.
    /// </summary>
    public class SBOMValidationResult
    {
        /// <summary>
        /// True if the validation action was successful.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// Gets a list of errors that were encountered during the SBOM validation.
        /// </summary>
        public IList<EntityError> Errors { get; private set; }

        public SBOMValidationResult(bool isSuccessful, IList<EntityError> errors)
        {
            IsSuccessful = isSuccessful;
            Errors = errors ?? new List<EntityError>();
        }
    }
}
