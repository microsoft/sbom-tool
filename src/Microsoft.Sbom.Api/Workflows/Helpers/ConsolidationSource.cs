// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// A class that lets us track information about the source artifact that feeds into a consolidated SBOM.
/// </summary>
internal class ConsolidationSource
{
    public ArtifactInfo ArtifactInfo { get; }

    public ISbomConfig SbomConfig { get; }

    public string BuildDropPath { get; }

    public ConsolidationSource(ArtifactInfo artifactInfo, ISbomConfig sbomConfig, string buildDropPath)
    {
        ArtifactInfo = artifactInfo ?? throw new ArgumentNullException(nameof(artifactInfo));
        SbomConfig = sbomConfig ?? throw new ArgumentNullException(nameof(sbomConfig));
        BuildDropPath = buildDropPath ?? throw new ArgumentNullException(nameof(buildDropPath));
    }

    public override string ToString()
    {
        return $"ConsolidationSource: {ArtifactInfo}, ManifestInfo: {SbomConfig.ManifestInfo}";
    }
}
