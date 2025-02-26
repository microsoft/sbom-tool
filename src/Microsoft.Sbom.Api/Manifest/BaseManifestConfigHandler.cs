// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

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

    protected string CatalogFilePath => fileSystemUtils.JoinPaths(SbomDirPath, Constants.CatalogFileName);

    protected string BsiFilePath => fileSystemUtils.JoinPaths(SbomDirPath, Constants.BsiFileName);

    protected IMetadataBuilder MetadataBuilder => metadataBuilderFactory.Get(ManifestInfo);

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

    public virtual bool TryGetManifestConfig(out ISbomConfig sbomConfig)
    {
        sbomConfig = CreateSbomConfig();

        // For generation the default behavior is to always return true
        // as we generate all the current formats of SBOM. Only override if the -mi
        // argument is specified.
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            if (configuration.ManifestInfo?.Value != null
                && !configuration.ManifestInfo.Value.Contains(Constants.SPDX30ManifestInfo))
            {
                return false;
            }

            return true;
        }

        if (configuration.ManifestToolAction == ManifestToolActions.Validate)
        {
            // We can only validate one format at a time, so check if its this one and return true/false.
            if (configuration.ManifestInfo?.Value != null
               && configuration.ManifestInfo.Value.Count == 1
               && configuration.ManifestInfo.Value.Contains(Constants.SPDX30ManifestInfo))
            {
                return true;
            }

            return false;
        }

        sbomConfig = null;
        return false;
    }
}
