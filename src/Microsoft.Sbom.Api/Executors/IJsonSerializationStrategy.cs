// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions;

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
    /// Adds a metadata dictionary as a JSON element to the SBOM, if required by this format.
    /// </summary>
    /// <param name="sbomConfigs"></param>
    /// <param name="config"></param>
    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config);

    /// <summary>
    /// Starts an array with a graph header, if required by this format.
    /// </summary>
    /// <param name="sbomConfig"></param>
    public void StartGraphArray(ISbomConfig sbomConfig);

    /// <summary>
    /// Ends an array with a graph header, if required by this format.
    /// </summary>
    /// <param name="sbomConfig"></param>
    public void EndGraphArray(ISbomConfig sbomConfig);

    public void WriteJsonObjectsToManifest(GenerationResult generationResult, ISbomConfig config, HashSet<string> elementsSpdxIdList);
}
