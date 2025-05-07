// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

internal interface IJsonSerializationStrategy
{
    /// <summary>
    /// Adds the config to the list of configs that support files.
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns></returns>
    public bool AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    /// <summary>
    /// Adds the config to the list of configs that support packages.
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns></returns>
    public bool AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    /// <summary>
    /// Adds the config to the list of configs that support relationships.
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns></returns>
    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    /// <summary>
    /// Adds the config to the list of configs that support external document references.
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns></returns>
    public bool AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    /// <summary>
    /// Adds a metadata dictionary as a JSON element to the SBOM.
    /// This is only used for SPDX 2.2 SBOM generation, metadata is added differently for SPDX 3.0 and above.
    /// </summary>
    /// <param name="sbomConfigs"></param>
    /// <param name="config"></param>
    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config);

    /// <summary>
    /// Starts an array with a graph header that is only used in SPDX 3.0 and above.
    /// This does not apply to SPDX 2.2 SBOM generation.
    /// </summary>
    /// <param name="manifestInfosFromConfig"></param>
    /// <param name="sbomConfigs"></param>
    public void StartGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs);

    /// <summary>
    /// Ends an array with a graph header that is only used in SPDX 3.0 and above.
    /// This does not apply to SPDX 2.2 SBOM generation.
    /// </summary>
    /// <param name="manifestInfosFromConfig"></param>
    /// <param name="sbomConfigs"></param>
    public void EndGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs);

    public void WriteJsonObjectsToManifest(GenerationResult generationResult, HashSet<string> elementsSpdxIdList);
}
