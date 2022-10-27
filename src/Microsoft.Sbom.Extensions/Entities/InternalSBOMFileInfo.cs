// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Entities;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// InternalSBOMFileInfo class used for processing and storing extra data during the generation process.
    /// </summary>
    public class InternalSBOMFileInfo
    {
        /// <summary>
        /// Gets or sets a list of the checksums for the file.
        /// </summary>
        public IEnumerable<Checksum> Checksum { get; set; }

        /// <summary>
        /// Gets or sets copyright holder of the file, as well as any dates present.
        /// </summary>
        public string FileCopyrightText { get; set; }

        /// <summary>
        /// Gets or sets contain the license the file creator has concluded or alternative values.
        /// </summary>
        public string LicenseConcluded { get; set; }

        /// <summary>
        /// Gets or sets contains any license information actually found in the file. 
        /// </summary>
        public List<string> LicenseInfoInFiles { get; set; }

        /// <summary>
        /// Gets or sets the relative path to the BuildDropPath of the file in the SBOM.
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether determines if that file is in the BuildDropPath.
        /// </summary>
        public bool IsOutsideDropPath { get; set; }

        /// <summary>
        /// Gets or sets contains the list of file types for this file.
        /// </summary>
        public List<FileType> FileTypes { get; set; }

        public FileLocation FileLocation { get; set; }
    }
}
