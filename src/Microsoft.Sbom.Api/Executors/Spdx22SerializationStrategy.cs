// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 2.2.
/// </summary>
internal class Spdx22SerializationStrategy : IJsonSerializationStrategy
{
    public bool AddToFilesSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetFilesArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
            return true;
        }

        return false;
    }

    public bool AddToPackagesSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetPackageArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
            return true;
        }

        return false;
    }

    public bool AddToRelationshipsSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetRelationshipsHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            return true;
        }

        return false;
    }

    public bool AddToExternalDocRefsSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetExternalRefArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
            return true;
        }

        return false;
    }

    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config)
    {
        config.JsonSerializer?.WriteJsonString(config.MetadataBuilder.GetHeaderJsonString(sbomConfigs));
    }

    public void StartGraphArray(ISbomConfig sbomConfig)
    {
        // Not supported for SPDX 2.2.
    }

    public void EndGraphArray(ISbomConfig sbomConfig)
    {
        // Not supported for SPDX 2.2.
    }

    /// <summary>
    /// Writes the json objects to the manifest in SPDX 2.2 format.
    /// </summary>
    /// <param name="generationResult"></param>
    /// <param name="config"></param>
    /// <param name="elementsSpdxIdList">Not used for deduplication. Only used for >= SPDX 3.0.</param>
    public void WriteJsonObjectsToManifest(GenerationResult generationResult, ISbomConfig config, ISet<string> elementsSpdxIdList)
    {
        var serializer = config.JsonSerializer;

        if (generationResult.SerializerToJsonDocuments.TryGetValue(serializer, out var jsonDocuments))
        {
            if (jsonDocuments.Count > 0)
            {
                foreach (var jsonDocument in jsonDocuments)
                {
                    serializer.Write(jsonDocument);
                }
            }
        }

        var jsonArrayStarted = generationResult.JsonArrayStartedForConfig[config];
        if (jsonArrayStarted)
        {
            config.JsonSerializer.EndJsonArray();
        }
    }
}
