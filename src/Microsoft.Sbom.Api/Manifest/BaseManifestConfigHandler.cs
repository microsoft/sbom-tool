// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;

/// <summary>
/// Provides the base class for ManifestConfig handlers.
/// </summary>
public abstract class BaseManifestConfigHandler : IManifestConfigHandler
{
    protected readonly IMetadataBuilderFactory metadataBuilderFactory;
    protected readonly IConfiguration configuration;
    protected readonly IFileSystemUtils fileSystemUtils;

    protected BaseManifestConfigHandler(
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory)
    {
        this.metadataBuilderFactory = metadataBuilderFactory ?? throw new ArgumentException(nameof(metadataBuilderFactory));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    protected abstract ManifestInfo ManifestInfo { get; }

    protected string ManifestDirPath => configuration.ManifestDirPath?.Value;

    protected string SbomDirPath => fileSystemUtils.JoinPaths(ManifestDirPath, $"{ManifestInfo.Name.ToLower()}_{ManifestInfo.Version.ToLower()}");

    protected string SbomFilePath => fileSystemUtils.JoinPaths(SbomDirPath, $"manifest.{ManifestInfo.Name.ToLower()}.json");

    protected string ManifestJsonSha256FilePath => $"{SbomFilePath}.sha256";

    protected string CatalogFilePath => fileSystemUtils.JoinPaths(SbomDirPath, SpdxConstants.CatalogFileName);

    protected string BsiFilePath => fileSystemUtils.JoinPaths(SbomDirPath, SpdxConstants.BsiFileName);

    protected IMetadataBuilder MetadataBuilder => metadataBuilderFactory.Get(ManifestInfo);

    public abstract bool TryGetManifestConfig(out ISbomConfig sbomConfig);

    protected ISbomConfig CreateSbomConfig()
    {
        return new SbomConfig(fileSystemUtils)
        {
            ManifestInfo = ManifestInfo,
            ManifestJsonDirPath = SbomDirPath,
            ManifestJsonFilePath = SbomFilePath,
            CatalogFilePath = CatalogFilePath,
            BsiFilePath = BsiFilePath,
            ManifestJsonFileSha256FilePath = ManifestJsonSha256FilePath,
            MetadataBuilder = MetadataBuilder,
            Recorder = new SbomPackageDetailsRecorder()
        };
    }
}
