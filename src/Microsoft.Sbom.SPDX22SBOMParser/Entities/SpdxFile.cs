﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.SPDX22SBOMParser.Entities.Enums;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    public class SPDXFile
    {
        /// <summary>
        /// Identify the full path and filename that corresponds to the file information.
        /// </summary>
        [JsonPropertyName("fileName")]
        public string FileName { get; set; }

        /// <summary>
        /// Unique Identifier for elements in SPDX document.
        /// </summary>
        [JsonPropertyName("SPDXID")]
        public string SPDXId { get; set; }

        /// <summary>
        /// Provide a unique identifier to match analysis information on each specific file in a package.
        /// </summary>    
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("checksums")]
        public List<Checksum> FileChecksums { get; set; }

        /// <summary>
        /// Contain the license the SPDX file creator has concluded as the package or alternative values.
        /// </summary>
        [JsonPropertyName("licenseConcluded")]
        public string LicenseConcluded { get; set; }

        /// <summary>
        /// Contains the license information actually found in the file, if any. 
        /// </summary>
        [JsonPropertyName("licenseInfoInFiles")]
        public List<string> LicenseInfoInFiles { get; set; }

        /// <summary>
        /// Copyright holder of the package, as well as any dates present.
        /// </summary>
        [JsonPropertyName("copyrightText")]
        public string FileCopyrightText { get; set; }

        /// <summary>
        /// Provides a reasonable estimation of the file type.
        /// </summary>
        [JsonPropertyName("fileTypes")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<SPDXFileType> FileTypes { get; set; }
    }
}
