// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// A data structure that is used to store the data generated during SBOM generation.
    /// </summary>
    public class GenerationData // TODO: Move to contracts
    {
        /// <summary>
        /// A list of checksums for all the files that were traversed during SBOM generation.
        /// </summary>
        public IList<Checksum[]> Checksums { get; set; }

        /// <summary>
        /// A list of all the unique ids that were generated for each
        /// file that was traversed for the root package of the SBOM.
        /// </summary>
        public IList<string> FileIds { get; set; }

        /// <summary>
        /// A list of unique ids that were generated for each
        /// file of SPDX file type that was traversed for this SBOM.
        /// </summary>
        public IList<string> SPDXFileIds { get; set; }

        /// <summary>
        /// A list of all the unique ids that were generated for each package that was 
        /// traversed for this SBOM.
        /// </summary>
        public IList<string> PackageIds { get; set; }

        /// <summary>
        /// A list of pairs of ExternalDocumentReference IDs and described element IDs that are referenced in the SBOM.
        /// </summary>
        public IList<KeyValuePair<string, string>> ExternalDocumentReferenceIDs { get; set; }

        /// <summary>
        /// The id of the root package in this SBOM
        /// </summary>
        public string RootPackageId { get; set; }

        /// <summary>
        /// The id of the SBOM document
        /// </summary>
        public string DocumentId { get; set; }
    }
}
