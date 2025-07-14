// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Manifest;

public interface IManifestGeneratorProvider
{
    public IManifestGenerator Get(ManifestInfo manifestInfo);

    public IEnumerable<ManifestInfo> GetSupportedManifestInfos();

    public ManifestGeneratorProvider Init();
}
