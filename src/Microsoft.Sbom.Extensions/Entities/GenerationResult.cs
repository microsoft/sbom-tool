// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text.Json;

namespace Microsoft.Sbom.Entities
{
    /// <summary>
    /// A object that represents the generated <see cref="JsonDocument"/> along
    /// with additional metadata about the generated object.
    /// </summary>
    public class GenerationResult
    {
        private JsonDocument document;

        /// <summary>
        /// Gets or sets the entity object in the JSON format as expected by the current SBOM format.
        /// </summary>
        public JsonDocument Document
        {
            get
            {
                return document;
            }

            set
            {
                document = value ?? throw new Exception("JsonDocument cannot be null.");
            }
        }

        /// <summary>
        /// Gets or sets any additional metadata that needs to be returned about the current
        /// entity or SBOM.
        /// </summary>
        public ResultMetadata ResultMetadata { get; set; }
    }
}
