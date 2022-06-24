﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions
{
    /// <summary>
    /// Provides metadata about the environment where this SBOM was generated.
    /// </summary>
    public interface IMetadataProvider
    {
        /// <summary>
        /// Gets or sets stores the metadata that is generated by this metadata provider.
        /// </summary>
        IDictionary<MetadataKey, object> MetadataDictionary { get; set; }

        /// <summary>
        /// Gets the namespace URI for the SBOM document that is unique within this build environment. 
        /// </summary>
        public string GetDocumentNamespaceUri();

        /// <summary>
        /// Gets the name of the build environment for which this provider should be used.
        /// </summary>
        public string BuildEnvironmentName { get; }
    }
}
