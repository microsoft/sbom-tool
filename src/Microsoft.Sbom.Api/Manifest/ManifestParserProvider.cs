// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Manifest;

/// <summary>
/// Builds a map of <see cref="ManifestInfo"/>s to the actual <see cref="ManifestInterface"/> objects.
/// </summary>
public class ManifestParserProvider : IManifestParserProvider
{
    private readonly IEnumerable<IManifestInterface> manifestInterfaces;
    private readonly IDictionary<string, IManifestInterface> manifestMap;

    public ManifestParserProvider(IEnumerable<IManifestInterface> manifestInterfaces)
    {
        this.manifestInterfaces = manifestInterfaces;
        manifestMap = new Dictionary<string, IManifestInterface>(StringComparer.OrdinalIgnoreCase);
        this.Init();
    }

    public void Init()
    {
        foreach (var manifestInterface in manifestInterfaces)
        {
            var supportedManifestFormats = manifestInterface.RegisterManifest();
            foreach (var manifestFormat in supportedManifestFormats)
            {
                // TODO implement getHashCode() in manifest interface.
                manifestMap[$"{manifestFormat.Name}:{manifestFormat.Version}"] = manifestInterface;
            }
        }
    }

    public IManifestInterface Get(ManifestInfo manifestInfo)
    {
        return manifestMap[$"{manifestInfo.Name}:{manifestInfo.Version}"];
    }
}