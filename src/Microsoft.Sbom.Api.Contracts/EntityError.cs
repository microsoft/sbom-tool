// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Contracts.Entities;
using Microsoft.Sbom.Api.Contracts.Enums;

namespace Microsoft.Sbom.Api.Contracts
{
    /// <summary>
    /// Represents a single error for a given entity. The entity could be a file or package.
    /// </summary>
    public class EntityError
    {
        /// <summary>
        /// Gets or sets the type of error.
        /// </summary>
        public ErrorType ErrorType { get; set; }

        /// <summary>
        /// Gets or sets the entity that encountered the error.
        /// </summary>
        public Entity Entity { get; set; }

        /// <summary>
        /// Gets or sets the details of the error.
        /// </summary>
        public string Details { get; set; }
    }
}
