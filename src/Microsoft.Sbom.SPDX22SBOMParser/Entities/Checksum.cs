// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Represents the hash value of the file using the algorithm specified.
    /// </summary>
    public class Checksum
    {
        /// <summary>
        /// Gets or sets the name of the hash algorithm.
        /// </summary>
        [JsonPropertyName("algorithm")]

        public string Algorithm { get; set; }

        /// <summary>
        /// Gets or sets the string value of the computed hash.
        /// </summary>
        [JsonPropertyName("checksumValue")]
        public string ChecksumValue { get; set; }
    }
}
