using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts.Entities
{
    /// <summary>
    /// Represents a single entity in a SBOM, such as a file or package.
    /// </summary>
    public abstract class Entity
    {
        /// <summary>
        /// The type of the entity.
        /// </summary>
        public EntityType EntityType { get; private set; }

        public string Id { get; private set; }

        protected Entity(EntityType entityType, string id = null)
        {
            EntityType = entityType;
            Id = id;
        }
    }
}
