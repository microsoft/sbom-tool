// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts.Entities
{
    /// <summary>
    /// Represents a single entity in a SBOM, such as a file or package.
    /// </summary>
    public abstract class Entity
    {
        /// <summary>
        /// Gets the type of the entity.
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
