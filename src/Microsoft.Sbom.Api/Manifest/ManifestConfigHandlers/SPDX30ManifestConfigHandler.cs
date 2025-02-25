// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers;

/// <summary>
/// Provides the ManifestConfig for the SPDX 3.0 format.
/// </summary>
public class SPDX30ManifestConfigHandler : BaseManifestConfigHandler
{
    public SPDX30ManifestConfigHandler(
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils,
        IMetadataBuilderFactory metadataBuilderFactory)
        : base(configuration, fileSystemUtils, metadataBuilderFactory)
    {
    }

    /// <inheritdoc/>
    protected override ManifestInfo ManifestInfo => SpdxConstants.SPDX30ManifestInfo;

    public override bool TryGetManifestConfig(out ISbomConfig sbomConfig)
    {
        sbomConfig = CreateSbomConfig();

        // For generation the default behavior is to always return true
        // as we generate all the current formats of SBOM. Only override if the -mi
        // argument is specified.
        if (configuration.ManifestToolAction == ManifestToolActions.Generate)
        {
            if (configuration.ManifestInfo?.Value != null
                && !configuration.ManifestInfo.Value.Contains(SpdxConstants.SPDX30ManifestInfo))
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
               && configuration.ManifestInfo.Value.Contains(SpdxConstants.SPDX30ManifestInfo))
            {
                return true;
            }

            return false;
        }

        sbomConfig = null;
        return false;
    }
}
