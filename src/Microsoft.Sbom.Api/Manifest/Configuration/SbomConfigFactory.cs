// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

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
        string bsiCoseFilePath,
        string manifestCoseFilePath,
        ISbomPackageDetailsRecorder recorder,
        IMetadataBuilder metadataBuilder)
    {
        return new SbomConfig(fileSystemUtils)
        {
            ManifestInfo = manifestInfo,
            ManifestJsonDirPath = manifestDirPath,
            ManifestJsonFilePath = manifestFilePath,
            BsiFilePath = bsiFilePath,
            BsiCoseFilePath = bsiCoseFilePath,
            ManifestCoseFilePath = manifestCoseFilePath,
            CatalogFilePath = catalogFilePath,
            ManifestJsonFileSha256FilePath = manifestFileSha256HashPath,
            MetadataBuilder = metadataBuilder,
            Recorder = recorder
        };
    }

    public ISbomConfig Get(
        ManifestInfo manifestInfo,
        string manifestPath,
        IMetadataBuilderFactory metadataBuilderFactory)
    {
        var sbomDirPath = GetSpdxDirPath(manifestPath, manifestInfo);
        var sbomFilePath = GetSbomFilePath(manifestPath, manifestInfo);
        var shaFilePath = $"{sbomFilePath}.sha256";
        var catFilePath = fileSystemUtils.JoinPaths(sbomDirPath, Constants.CatalogFileName);
        var bsiFilePath = fileSystemUtils.JoinPaths(sbomDirPath, Constants.BsiFileName);
        var bsiCoseFilePath = fileSystemUtils.JoinPaths(sbomDirPath, Constants.BsiCoseFileName);
        var manifestCoseFilePath = fileSystemUtils.JoinPaths(sbomDirPath, Constants.ManifestCoseFileName);
        if (!fileSystemUtils.FileExists(shaFilePath) && !fileSystemUtils.FileExists(catFilePath) && !fileSystemUtils.FileExists(bsiFilePath))
        {
            // This is likely a CloudBuild SBOM, adjust paths accordingly
            shaFilePath = null;
            catFilePath = fileSystemUtils.JoinPaths(manifestPath, Constants.CatalogFileName);
            bsiFilePath = fileSystemUtils.JoinPaths(manifestPath, Constants.BsiFileName);
        }

        return Get(manifestInfo,
            manifestPath,
            sbomFilePath,
            shaFilePath,
            catFilePath,
            bsiFilePath,
            bsiCoseFilePath,
            manifestCoseFilePath,
            new SbomPackageDetailsRecorder(),
            metadataBuilderFactory.Get(manifestInfo));
    }

    public string GetSpdxDirPath(string manifestDirPath, ManifestInfo manifestInfo) => fileSystemUtils.JoinPaths(
        manifestDirPath,
        $"{manifestInfo.Name.ToLower()}_{manifestInfo.Version.ToLower()}");

    public string GetSbomFilePath(string manifestDirPath, ManifestInfo manifestInfo) => fileSystemUtils.JoinPaths(
        GetSpdxDirPath(manifestDirPath, manifestInfo),
        $"manifest.{manifestInfo.Name.ToLower()}.json");
}
