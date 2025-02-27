// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

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
    protected override ManifestInfo ManifestInfo => Constants.SPDX30ManifestInfo;
}
