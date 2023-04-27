// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;

/// <summary>
/// Provides the ManifestConfig for the SPDX 2.2 format.
/// </summary>
public class SPDX22ManifestConfigHandler : IManifestConfigHandler
{
    private readonly IMetadataBuilderFactory metadataBuilderFactory;
    private readonly IConfiguration configuration;
    private readonly IFileSystemUtils fileSystemUtils;

    private string ManifestDirPath => configuration.ManifestDirPath?.Value;

    // directory path for SPDX 2.2 is 
    // root/_manifest/spdx_2.2/
    private string SbomDirPath => fileSystemUtils.JoinPaths(ManifestDirPath, $"{Constants.SPDX22ManifestInfo.Name.ToLower()}_{Constants.SPDX22ManifestInfo.Version.ToLower()}");

    // sbom file path is manifest.spdx.json in the sbom directory.
    private string SbomFilePath => fileSystemUtils.JoinPaths(SbomDirPath, $"manifest.{Constants.SPDX22ManifestInfo.Name.ToLower()}.json");

    // sha file is sbom file + .sha256
    private string ManifestJsonSha256FilePath => $"{SbomFilePath}.sha256";

    // catalog file is always manifest.cat
    private string CatalogFilePath => fileSystemUtils.JoinPaths(SbomDirPath, Constants.CatalogFileName);

    // bsi.json file contains build session metadata and is always bsi.json
    private string BsiJsonFilePath => fileSystemUtils.JoinPaths(SbomDirPath, Constants.BsiFileName);

    private IMetadataBuilder MetadataBuilder => metadataBuilderFactory.Get(Constants.SPDX22ManifestInfo);

    public SPDX22ManifestConfigHandler(
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory)
    {
        this.metadataBuilderFactory = metadataBuilderFactory ?? throw new ArgumentException(nameof(metadataBuilderFactory));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public bool TryGetManifestConfig(out ISbomConfig sbomConfig)
    {
        sbomConfig = new SbomConfig(fileSystemUtils)
        {
            ManifestInfo = Constants.SPDX22ManifestInfo,
            ManifestJsonDirPath = SbomDirPath,
            ManifestJsonFilePath = SbomFilePath,
            CatalogFilePath = CatalogFilePath,
            BsiFilePath = BsiJsonFilePath,
            ManifestJsonFileSha256FilePath = ManifestJsonSha256FilePath,
            MetadataBuilder = MetadataBuilder,
            Recorder = new SbomPackageDetailsRecorder()
        };

        // For generation the default behavior is to always return true
        // as we generate all the current formats of SBOM. Only override if the -mi 
        // argument is specified.
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            if (configuration.ManifestInfo?.Value != null
                && !configuration.ManifestInfo.Value.Contains(Constants.SPDX22ManifestInfo))
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
               && configuration.ManifestInfo.Value.Contains(Constants.SPDX22ManifestInfo))
            {
                return true;
            }

            return false;
        }

        sbomConfig = null;
        return false;
    }
}