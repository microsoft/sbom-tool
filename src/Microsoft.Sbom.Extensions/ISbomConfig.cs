// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Entities;
using System;

namespace Microsoft.Sbom
{
    /// <summary>
    /// Represents a configuration object for a given SBOM Format. It holds all the 
    /// relevant serializers and generation data for the given SBOM format.
    /// </summary>
    public interface ISbomConfig : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Gets or sets absolute path of manifest json directory.
        /// </summary>
        public string ManifestJsonDirPath { get; set; }

        /// <summary>
        /// Gets or sets absolute path of the manfest json file.
        /// </summary>
        public string ManifestJsonFilePath { get; set; }

        /// <summary>
        /// Gets or sets derived manifestInfo or from configurations.
        /// </summary>
        public ManifestInfo ManifestInfo { get; set; }

        /// <summary>
        /// Gets or sets the metadata builder for this manifest format.
        /// </summary>
        public IMetadataBuilder MetadataBuilder { get; set; }

        /// <summary>
        /// Gets the generated manifest tool json serializer for this SBOM config.
        /// </summary>
        public IManifestToolJsonSerializer JsonSerializer { get; }

        /// <summary>
        /// Gets or sets records ids and generated package details for the current SBOM.
        /// </summary>
        public ISbomPackageDetailsRecorder Recorder { get; set; }

        /// <summary>
        /// Starts process of JSON serialization for the current SBOM.
        /// </summary>
        public void StartJsonSerialization();
    }
}
