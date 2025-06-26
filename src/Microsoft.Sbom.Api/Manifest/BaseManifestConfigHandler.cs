// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
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
    protected readonly IConfiguration configuration;
    protected readonly IFileSystemUtils fileSystemUtils;
    protected readonly ISbomConfigFactory sbomConfigFactory;

    protected BaseManifestConfigHandler(
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils,
        ISbomConfigFactory sbomConfigFactory)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.sbomConfigFactory = sbomConfigFactory ?? throw new ArgumentNullException(nameof(sbomConfigFactory));
    }

    protected abstract ManifestInfo ManifestInfo { get; }

    protected string ManifestDirPath => configuration.ManifestDirPath?.Value;

    protected ISbomConfig CreateSbomConfig()
    {
        return sbomConfigFactory.Get(ManifestInfo, ManifestDirPath);
    }

    public virtual bool TryGetManifestConfig(out ISbomConfig sbomConfig)
    {
        sbomConfig = CreateSbomConfig();

        // For generation the default behavior is to return the SPDX 2.2 SBOM.
        // Only override if the -mi argument is specified.
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            if (configuration.ManifestInfo?.Value != null
                && !Constants.SupportedSpdxManifests.Any(configuration.ManifestInfo.Value.Contains))
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
               && Constants.SupportedSpdxManifests.Any(configuration.ManifestInfo.Value.Contains))
            {
                return true;
            }

            return false;
        }

        sbomConfig = null;
        return false;
    }
}
