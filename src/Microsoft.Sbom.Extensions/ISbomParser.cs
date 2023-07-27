// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;

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
    ParserState Next();

    /// <summary>
    /// Returns a list of <see cref="SbomFile"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SbomFile> GetFiles();

    /// <summary>
    /// Returns a list of <see cref="SbomPackage"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SbomPackage> GetPackages();

    /// <summary>
    /// Returns a list of <see cref="SBOMRelationship"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SBOMRelationship> GetRelationships();

    /// <summary>
    /// Returns a list of <see cref="SBOMReference"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SBOMReference> GetReferences();

    /// <summary>
    /// Returns a <see cref="SBOMMetadata"/> object using the metadata defined in the 
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    Spdx22Metadata GetMetadata();

    /// <summary>
    /// This function is called by the sbom tool upon initialization to get all the 
    /// manifest versions this library can parse.
    /// </summary>
    /// <returns>An version sorted array in ascending order of 
    /// <see cref="ManifestInfo">manifests</see> this library can parse.</returns>
    ManifestInfo[] RegisterManifest();

    /// <summary>
    /// Get the current state of the parser.
    /// </summary>
    public ParserState CurrentState { get; }
}
