// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common;
using System;
using Microsoft.Sbom.Api.Utils.FileSystem;

namespace Microsoft.Sbom.Api.Manifest.Configuration
{
    public class SbomConfigFactory : ISbomConfigFactory
    {
        private readonly IFileSystemUtils fileSystemUtils;

        public SbomConfigFactory(IFileSystemUtils fileSystemUtils)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        public ISbomConfig Get(
            ManifestInfo manifestInfo,
            string manifestDirPath,
            string manifestFilePath,
            ISbomPackageDetailsRecorder recorder,
            IMetadataBuilder metadataBuilder)
        {
            return new SbomConfig(fileSystemUtils)
            {
                ManifestInfo = manifestInfo,
                ManifestJsonDirPath = manifestDirPath,
                ManifestJsonFilePath = manifestFilePath,
                MetadataBuilder = metadataBuilder,
                Recorder = recorder
            };
        }
    }
}
