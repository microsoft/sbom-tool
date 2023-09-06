// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// Interface for metadata builder that adds additional information to the SBOM.
/// as a header.
/// </summary>
public interface IMetadataBuilder
{
    /// <summary>
    /// Gets the json string value of the header dictionary.
    /// </summary>
    /// <returns></returns>
    string GetHeaderJsonString(IInternalMetadataProvider internalMetadataProvider);

    /// <summary>
    /// Gets name of file array header if supported.
    /// </summary>
    bool TryGetFilesArrayHeaderName(out string headerName);

    /// <summary>
    /// Gets name of package array header if supported.
    /// </summary>
    bool TryGetPackageArrayHeaderName(out string headerName);

    /// <summary>
    /// Gets name of external document reference array header if supported.
    /// </summary>
    bool TryGetExternalRefArrayHeaderName(out string headerName);

    /// <summary>
    /// Gets name of relationships array header if supported.
    /// </summary>
    bool TryGetRelationshipsHeaderName(out string headerName);

    /// <summary>
    /// Gets root package in JSON if supported.
    /// </summary>
    bool TryGetRootPackageJson(IInternalMetadataProvider internalMetadataProvider, out GenerationResult generationResult);
}
