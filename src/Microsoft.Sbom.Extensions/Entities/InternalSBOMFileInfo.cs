// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// InternalSBOMFileInfo class used for processing and storing extra data during the generation process.
    /// </summary>
    public class InternalSBOMFileInfo
    {
        /// <summary>
        /// A list of the checksums for the file.
        /// </summary>
        public IEnumerable<Checksum> Checksum { get; set; }

        /// <summary>
        /// Copyright holder of the file, as well as any dates present.
        /// </summary>
        public string FileCopyrightText { get; set; }

        /// <summary>
        /// Contain the license the file creator has concluded or alternative values.
        /// </summary>
        public string LicenseConcluded { get; set; }

        /// <summary>
        /// Contains any license information actually found in the file. 
        /// </summary>
        public List<string> LicenseInfoInFiles { get; set; }

        /// <summary>
        /// The relative path to the BuildDropPath of the file in the SBOM.
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Determines if that file is in the BuildDropPath.
        /// </summary>
        public bool IsOutsideDropPath { get; set; }

        /// <summary>
        /// Contains the list of file types for this file
        /// </summary>
        public List<FileType> FileTypes { get; set; }
    }
}
