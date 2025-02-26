// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;

namespace Microsoft.Sbom;

/// <summary>
/// Defines an interface that the SBOM tool uses to parse an SBOM.
/// </summary>
public interface ISbomParser
{
    /// <summary>
    /// Advance the parser to the next available state.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    ParserStateResult? Next();

    /// <summary>
    /// Returns a <see cref="SBOMMetadata"/> object using the metadata defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    SpdxMetadata GetMetadata();

    /// <summary>
    /// This function is called by the sbom tool upon initialization to get all the
    /// manifest versions this library can parse.
    /// </summary>
    /// <returns>An version sorted array in ascending order of
    /// <see cref="ManifestInfo">manifests</see> this library can parse.</returns>
    ManifestInfo[] RegisterManifest();

    /// <summary>
    /// Set compliance standard for SPDX 3.0 parsers and above.
    /// Returns the compliance standard set by the user, if it is valid.
    /// </summary>
    /// <param name="spdxVersion"></param>
    void SetComplianceStandard(string? complianceStandardFromCli);
}
