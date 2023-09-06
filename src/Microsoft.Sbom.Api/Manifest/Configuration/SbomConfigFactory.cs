// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Manifest.Configuration;

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
        string manifestFileSha256HashPath,
        string catalogFilePath,
        string bsiFilePath,
        ISbomPackageDetailsRecorder recorder,
        IMetadataBuilder metadataBuilder)
    {
        return new SbomConfig(fileSystemUtils)
        {
            ManifestInfo = manifestInfo,
            ManifestJsonDirPath = manifestDirPath,
            ManifestJsonFilePath = manifestFilePath,
            BsiFilePath = bsiFilePath,
            CatalogFilePath = catalogFilePath,
            ManifestJsonFileSha256FilePath = manifestFileSha256HashPath,
            MetadataBuilder = metadataBuilder,
            Recorder = recorder
        };
    }
}
