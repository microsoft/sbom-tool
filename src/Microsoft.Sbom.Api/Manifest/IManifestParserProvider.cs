// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Manifest;

/// <summary>
/// Provides a factory method to get a parser for a given SBOM format.
/// </summary>
public interface IManifestParserProvider
{
    public IManifestInterface Get(ManifestInfo manifestInfo);

    public void Init();
}
