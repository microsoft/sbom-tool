﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using System.Collections.Generic;
using System.IO;

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
    /// Returns a list of <see cref="SBOMFile"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SBOMFile> GetFiles();

    /// <summary>
    /// Returns a list of <see cref="SBOMPackage"/> objects defined in the
    /// current SBOM.
    /// </summary>
    /// <param name="stream"></param>
    /// <returns></returns>
    IEnumerable<SBOMPackage> GetPackages();

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
    SBOMMetadata GetMetadata();

    /// <summary>
    /// This function is called by the sbom tool upon initialization to get all the 
    /// manifest versions this library can parse.
    /// </summary>
    /// <returns>An version sorted array in ascending order of 
    /// <see cref="ManifestInfo">manifests</see> this library can parse.</returns>
    ManifestInfo[] RegisterManifest();
}
