// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Common;

/// <summary>
/// Factory that instantiate ISbomConfig based on parameters.
/// </summary>
public interface ISbomConfigFactory
{
    /// <summary>
    /// Gets new instance of ISbomConfig.
    /// </summary>
    public ISbomConfig Get(
        ManifestInfo manifestInfo,
        string manifestDirPath,
        string manifestFilePath,
        string manifestFileSha256HashPath,
        string catalogFilePath,
        string bsiFilePath,
        ISbomPackageDetailsRecorder recorder,
        IMetadataBuilder metadataBuilder);

    public ISbomConfig Get(
        ManifestInfo manifestInfo,
        string manifestPath,
        IMetadataBuilderFactory metadataBuilderFactory);

    public string GetSbomDirPath(string manifestDirPath, ManifestInfo manifestInfo);

    public string GetSbomFilePath(string manifestDirPath, ManifestInfo manifestInfo);
}
