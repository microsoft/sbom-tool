// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// A list of metadata about the current entity being serialized. This can be
    /// identifiers generated for the entity or any additional metadata.
    /// </summary>
    public class ResultMetadata
    {
        /// <summary>
        /// The generated id of the current entity.
        /// </summary>
        public string EntityId { get; set; }

        /// <summary>
        /// The generated id of the current SBOM document.
        /// </summary>
        public string DocumentId { get; set; }
    }
}
