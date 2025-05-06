// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

internal interface IJsonSerializationStrategy
{
    public bool AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public bool AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public bool AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config);

    public void StartGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs);

    public void EndGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs);

    public void WriteJsonObjectsToManifest(GenerationResult generationResult, HashSet<string> elementsSpdxIdList);
}
