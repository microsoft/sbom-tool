// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common;
using System;

namespace Microsoft.Sbom.Api.Manifest.Configuration
{
    public class SbomConfigFactory : ISbomConfigFactory
    {
        private readonly IFileSystemUtils _fileSystemUtils;

        public SbomConfigFactory(IFileSystemUtils fileSystemUtils)
        {
            _fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        public ISbomConfig Get(
            ManifestInfo manifestInfo,
            string manifestDirPath,
            string manifestFilePath,
            ISbomPackageDetailsRecorder recorder,
            IMetadataBuilder metadataBuilder
        )
        {
            return new SbomConfig(_fileSystemUtils)
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
