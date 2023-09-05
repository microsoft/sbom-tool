// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Common;

/// <summary>
/// Builds a <see cref="MetadataBuilder"/> object for a given SBOM format.
/// </summary>
public interface IMetadataBuilderFactory
{
    /// <summary>
    /// Get the <see cref="MetadataBuilder"/> object for the given SBOM format.
    /// </summary>
    /// <param name="manifestInfo"></param>
    /// <returns></returns>
    IMetadataBuilder Get(ManifestInfo manifestInfo);
}
