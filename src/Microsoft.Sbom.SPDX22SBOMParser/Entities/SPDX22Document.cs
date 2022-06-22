// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    internal class SPDX22Document
    {
        /// <summary>
        /// Reference number for the version to understand how to parse and interpret the format.
        /// </summary>
        [JsonPropertyName("spdxVersion")]
        public string SPDXVersion { get; set; }

        /// <summary>
        /// License for compliance with the SPDX specification
        /// </summary>
        [JsonPropertyName("dataLicense")]
        public string DataLicense { get; set; }

        /// <summary>
        /// Unique Identifier for elements in SPDX document.
        /// </summary>
        public string SPDXID { get; set; }

        /// <summary>
        /// Identify name of this document as designated by creator.
        /// </summary>
        [JsonPropertyName("name")]
        public string DocumentName { get; set; }

        /// <summary>
        /// SPDX document specific namespace as a URI
        /// </summary>
        [JsonPropertyName("documentNamespace")]
        public string DocumentNamespace { get; set; }

        /// <summary>
        /// Provides the necessary information for forward and backward compatibility for processing tools.
        /// </summary>
        [JsonPropertyName("creationInfo")]
        public CreationInfo CreationInfo { get; set; }

        /// <summary>
        /// Files referenced in the SPDX document.
        /// </summary>
        [JsonPropertyName("files")]
        public List<SPDXFile> Files { get; set; }

        /// <summary>
        /// Packages referenced in the SPDX document.
        /// </summary>
        [JsonPropertyName("packages")]
        public List<SPDXPackage> Packages { get; set; }
    }
}
