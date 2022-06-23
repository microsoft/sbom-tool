// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// The manifest object that is returned by the parser.
    /// </summary>
    public class ManifestData // TODO:  move to contracts
    {
        /// <summary>
        /// Gets or sets the count of the number of files in this manifest.
        /// </summary>
        public int Count { get; set; }

        /// <summary>
        /// Gets or sets a dictionary with the key as the relative path of a file,
        /// and as list of <see cref="Checksum"/> for that file.
        /// </summary>
        public IDictionary<string, Microsoft.Sbom.Contracts.Checksum[]> HashesMap { get; set; }

        /// <summary>
        /// Gets or sets the manifest info object that identifies the current manifest.
        /// </summary>
        public ManifestInfo ManifestInfo { get; set; }
    }
}
