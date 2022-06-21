using Microsoft.Sbom.Contracts.Entities;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents a single error for a given entity. The entity could be a file or package.
    /// </summary>
    public class EntityError
    {
        /// <summary>
        /// The type of error
        /// </summary>
        public ErrorType ErrorType { get; set; }

        /// <summary>
        /// The entity that encountered the error.
        /// </summary>
        public Entity Entity { get; set; }

        /// <summary>
        /// The details of the error.
        /// </summary>
        public string Details { get; set; }
    }
}
