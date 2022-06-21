using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents the result of a SBOM generation action.
    /// </summary>
    public class SBOMGenerationResult
    {
        /// <summary>
        /// Is set to true if the SBOM generation was successful, that is when 
        /// the <see cref="Errors"/> list is empty.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// A list of errors that were encountered during the SBOM generation.
        /// </summary>
        public IList<EntityError> Errors { get; private set; }

        public SBOMGenerationResult(bool isSuccessful, IList<EntityError> errors)
        {
            IsSuccessful = isSuccessful;
            Errors = errors ?? new List<EntityError>();
        }
    }
}
